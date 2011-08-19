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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/llite/rw.c
 *
 * Lustre Lite I/O page cache routines shared by different kernel revs
 */

#include <linux/autoconf.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>
/* current_is_kswapd() */
#include <linux/swap.h>

#define DEBUG_SUBSYSTEM S_LLITE

//#include <lustre_mdc.h>
#include <lustre_lite.h>
#include <obd_cksum.h>
#include "llite_internal.h"
#include <linux/lustre_compat25.h>

/* this isn't where truncate starts.   roughly:
 * sys_truncate->ll_setattr_raw->vmtruncate->ll_truncate. setattr_raw grabs
 * DLM lock on [size, EOF], i_mutex, ->lli_size_sem, and WRITE_I_ALLOC_SEM to
 * avoid races.
 *
 * must be called under ->lli_size_sem */
void ll_truncate(struct inode *inode)
{
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p) to %Lu\n",inode->i_ino,
               inode->i_generation, inode, i_size_read(inode));

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_TRUNC, 1);

        EXIT;
        return;
} /* ll_truncate */

/**
 * Finalizes cl-data before exiting typical address_space operation. Dual to
 * ll_cl_init().
 */
static void ll_cl_fini(struct ll_cl_context *lcc)
{
        struct lu_env  *env  = lcc->lcc_env;
        struct cl_io   *io   = lcc->lcc_io;
        struct cl_page *page = lcc->lcc_page;

        LASSERT(lcc->lcc_cookie == current);
        LASSERT(env != NULL);

        if (page != NULL) {
                lu_ref_del(&page->cp_reference, "cl_io", io);
                cl_page_put(env, page);
        }

        if (io && lcc->lcc_created) {
                cl_io_end(env, io);
                cl_io_unlock(env, io);
                cl_io_iter_fini(env, io);
                cl_io_fini(env, io);
        }
        cl_env_put(env, &lcc->lcc_refcheck);
}

/**
 * Initializes common cl-data at the typical address_space operation entry
 * point.
 */
static struct ll_cl_context *ll_cl_init(struct file *file,
                                        struct page *vmpage, int create)
{
        struct ll_cl_context *lcc;
        struct lu_env    *env;
        struct cl_io     *io;
        struct cl_object *clob;
        struct ccc_io    *cio;

        int refcheck;
        int result = 0;

        clob = ll_i2info(vmpage->mapping->host)->lli_clob;
        LASSERT(clob != NULL);

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                return ERR_PTR(PTR_ERR(env));

        lcc = &vvp_env_info(env)->vti_io_ctx;
        memset(lcc, 0, sizeof(*lcc));
        lcc->lcc_env = env;
        lcc->lcc_refcheck = refcheck;
        lcc->lcc_cookie = current;

        cio = ccc_env_io(env);
        io = cio->cui_cl.cis_io;
        if (io == NULL && create) {
                struct vvp_io *vio;
                loff_t pos;

                /*
                 * Loop-back driver calls ->prepare_write() and ->sendfile()
                 * methods directly, bypassing file system ->write() operation,
                 * so cl_io has to be created here.
                 */

                io = ccc_env_thread_io(env);
                vio = vvp_env_io(env);
                ll_io_init(io, file, 1);

                /* No lock at all for this kind of IO - we can't do it because
                 * we have held page lock, it would cause deadlock.
                 * XXX: This causes poor performance to loop device - One page
                 *      per RPC.
                 *      In order to get better performance, users should use
                 *      lloop driver instead.
                 */
                io->ci_lockreq = CILR_NEVER;

                pos = (vmpage->index << CFS_PAGE_SHIFT);

                /* Create a temp IO to serve write. */
                result = cl_io_rw_init(env, io, CIT_WRITE, pos, CFS_PAGE_SIZE);
                if (result == 0) {
                        cio->cui_fd = LUSTRE_FPRIVATE(file);
                        cio->cui_iov = NULL;
                        cio->cui_nrsegs = 0;
                        result = cl_io_iter_init(env, io);
                        if (result == 0) {
                                result = cl_io_lock(env, io);
                                if (result == 0)
                                        result = cl_io_start(env, io);
                        }
                } else
                        result = io->ci_result;
                lcc->lcc_created = 1;
        }

        lcc->lcc_io = io;
        if (io == NULL)
                result = -EIO;
        if (result == 0) {
                struct cl_page   *page;

                LASSERT(io != NULL);
                LASSERT(io->ci_state == CIS_IO_GOING);
                LASSERT(cio->cui_fd == LUSTRE_FPRIVATE(file));
                page = cl_page_find(env, clob, vmpage->index, vmpage,
                                    CPT_CACHEABLE);
                if (!IS_ERR(page)) {
                        lcc->lcc_page = page;
                        lu_ref_add(&page->cp_reference, "cl_io", io);
                        result = 0;
                } else
                        result = PTR_ERR(page);
        }
        if (result) {
                ll_cl_fini(lcc);
                lcc = ERR_PTR(result);
        }

        CDEBUG(D_VFSTRACE, "%lu@"DFID" -> %d %p %p\n",
               vmpage->index, PFID(lu_object_fid(&clob->co_lu)), result,
               env, io);
        return lcc;
}

static struct ll_cl_context *ll_cl_get(void)
{
        struct ll_cl_context *lcc;
        struct lu_env *env;
        int refcheck;

        env = cl_env_get(&refcheck);
        LASSERT(!IS_ERR(env));
        lcc = &vvp_env_info(env)->vti_io_ctx;
        LASSERT(env == lcc->lcc_env);
        LASSERT(current == lcc->lcc_cookie);
        cl_env_put(env, &refcheck);

        /* env has got in ll_cl_init, so it is still usable. */
        return lcc;
}

/**
 * ->prepare_write() address space operation called by generic_file_write()
 * for every page during write.
 */
int ll_prepare_write(struct file *file, struct page *vmpage, unsigned from,
                     unsigned to)
{
        struct ll_cl_context *lcc;
        int result;
        ENTRY;

        lcc = ll_cl_init(file, vmpage, 1);
        if (!IS_ERR(lcc)) {
                struct lu_env  *env = lcc->lcc_env;
                struct cl_io   *io  = lcc->lcc_io;
                struct cl_page *page = lcc->lcc_page;

                cl_page_assume(env, io, page);
                if (cl_io_is_append(io)) {
                        struct cl_object   *obj   = io->ci_obj;
                        struct inode       *inode = ccc_object_inode(obj);
                        /**
                         * In VFS file->page write loop, for appending, the
                         * write offset might be reset according to the new
                         * file size before holding i_mutex. So crw_pos should
                         * be reset here. BUG:17711.
                         */
                        io->u.ci_wr.wr.crw_pos = i_size_read(inode);
                }
                result = cl_io_prepare_write(env, io, page, from, to);
                if (result == 0) {
                        /*
                         * Add a reference, so that page is not evicted from
                         * the cache until ->commit_write() is called.
                         */
                        cl_page_get(page);
                        lu_ref_add(&page->cp_reference, "prepare_write",
                                   cfs_current());
                } else {
                        cl_page_unassume(env, io, page);
                        ll_cl_fini(lcc);
                }
                /* returning 0 in prepare assumes commit must be called
                 * afterwards */
        } else {
                result = PTR_ERR(lcc);
        }
        RETURN(result);
}

int ll_commit_write(struct file *file, struct page *vmpage, unsigned from,
                    unsigned to)
{
        struct ll_cl_context *lcc;
        struct lu_env    *env;
        struct cl_io     *io;
        struct cl_page   *page;
        int result = 0;
        ENTRY;

        lcc  = ll_cl_get();
        env  = lcc->lcc_env;
        page = lcc->lcc_page;
        io   = lcc->lcc_io;

        LASSERT(cl_page_is_owned(page, io));
        LASSERT(from <= to);
        if (from != to) /* handle short write case. */
                result = cl_io_commit_write(env, io, page, from, to);
        if (cl_page_is_owned(page, io))
                cl_page_unassume(env, io, page);

        /*
         * Release reference acquired by ll_prepare_write().
         */
        lu_ref_del(&page->cp_reference, "prepare_write", cfs_current());
        cl_page_put(env, page);
        ll_cl_fini(lcc);
        RETURN(result);
}

struct obd_capa *cl_capa_lookup(struct inode *inode, enum cl_req_type crt)
{
        __u64 opc;

        opc = crt == CRT_WRITE ? CAPA_OPC_OSS_WRITE : CAPA_OPC_OSS_RW;
        return ll_osscapa_get(inode, opc);
}

static void ll_ra_stats_inc_sbi(struct ll_sb_info *sbi, enum ra_stat which);

/* WARNING: This algorithm is used to reduce the contention on
 * sbi->ll_lock. It should work well if the ra_max_pages is much
 * greater than the single file's read-ahead window.
 *
 * TODO: There may exist a `global sync problem' in this implementation.
 * Considering the global ra window is 100M, and each file's ra window is 10M,
 * there are over 10 files trying to get its ra budget and reach
 * ll_ra_count_get at the exactly same time. All of them will get a zero ra
 * window, although the global window is 100M. -jay
 */
static unsigned long ll_ra_count_get(struct ll_sb_info *sbi, unsigned long len)
{
        struct ll_ra_info *ra = &sbi->ll_ra_info;
        unsigned long ret;
        ENTRY;

        /**
         * If read-ahead pages left are less than 1M, do not do read-ahead,
         * otherwise it will form small read RPC(< 1M), which hurt server
         * performance a lot.
         */
        ret = min(ra->ra_max_pages - cfs_atomic_read(&ra->ra_cur_pages), len);
        if ((int)ret < 0 || ret < min((unsigned long)PTLRPC_MAX_BRW_PAGES, len))
                GOTO(out, ret = 0);

        if (cfs_atomic_add_return(ret, &ra->ra_cur_pages) > ra->ra_max_pages) {
                cfs_atomic_sub(ret, &ra->ra_cur_pages);
                ret = 0;
        }
out:
        RETURN(ret);
}

void ll_ra_count_put(struct ll_sb_info *sbi, unsigned long len)
{
        struct ll_ra_info *ra = &sbi->ll_ra_info;
        cfs_atomic_sub(len, &ra->ra_cur_pages);
}

static void ll_ra_stats_inc_sbi(struct ll_sb_info *sbi, enum ra_stat which)
{
        LASSERTF(which >= 0 && which < _NR_RA_STAT, "which: %u\n", which);
        lprocfs_counter_incr(sbi->ll_ra_stats, which);
}

void ll_ra_stats_inc(struct address_space *mapping, enum ra_stat which)
{
        struct ll_sb_info *sbi = ll_i2sbi(mapping->host);
        ll_ra_stats_inc_sbi(sbi, which);
}

#define RAS_CDEBUG(ras) \
        CDEBUG(D_READA,                                                      \
               "lrp %lu cr %lu cp %lu ws %lu wl %lu nra %lu r %lu ri %lu"    \
               "csr %lu sf %lu sp %lu sl %lu \n",                            \
               ras->ras_last_readpage, ras->ras_consecutive_requests,        \
               ras->ras_consecutive_pages, ras->ras_window_start,            \
               ras->ras_window_len, ras->ras_next_readahead,                 \
               ras->ras_requests, ras->ras_request_index,                    \
               ras->ras_consecutive_stride_requests, ras->ras_stride_offset, \
               ras->ras_stride_pages, ras->ras_stride_length)

static int index_in_window(unsigned long index, unsigned long point,
                           unsigned long before, unsigned long after)
{
        unsigned long start = point - before, end = point + after;

        if (start > point)
               start = 0;
        if (end < point)
               end = ~0;

        return start <= index && index <= end;
}

static struct ll_readahead_state *ll_ras_get(struct file *f)
{
        struct ll_file_data       *fd;

        fd = LUSTRE_FPRIVATE(f);
        return &fd->fd_ras;
}

void ll_ra_read_in(struct file *f, struct ll_ra_read *rar)
{
        struct ll_readahead_state *ras;

        ras = ll_ras_get(f);

        cfs_spin_lock(&ras->ras_lock);
        ras->ras_requests++;
        ras->ras_request_index = 0;
        ras->ras_consecutive_requests++;
        rar->lrr_reader = current;

        cfs_list_add(&rar->lrr_linkage, &ras->ras_read_beads);
        cfs_spin_unlock(&ras->ras_lock);
}

void ll_ra_read_ex(struct file *f, struct ll_ra_read *rar)
{
        struct ll_readahead_state *ras;

        ras = ll_ras_get(f);

        cfs_spin_lock(&ras->ras_lock);
        cfs_list_del_init(&rar->lrr_linkage);
        cfs_spin_unlock(&ras->ras_lock);
}

static struct ll_ra_read *ll_ra_read_get_locked(struct ll_readahead_state *ras)
{
        struct ll_ra_read *scan;

        cfs_list_for_each_entry(scan, &ras->ras_read_beads, lrr_linkage) {
                if (scan->lrr_reader == current)
                        return scan;
        }
        return NULL;
}

struct ll_ra_read *ll_ra_read_get(struct file *f)
{
        struct ll_readahead_state *ras;
        struct ll_ra_read         *bead;

        ras = ll_ras_get(f);

        cfs_spin_lock(&ras->ras_lock);
        bead = ll_ra_read_get_locked(ras);
        cfs_spin_unlock(&ras->ras_lock);
        return bead;
}

static int cl_read_ahead_page(const struct lu_env *env, struct cl_io *io,
                              struct cl_page_list *queue, struct cl_page *page,
                              struct page *vmpage)
{
        struct ccc_page *cp;
        int              rc;

        ENTRY;

        rc = 0;
        cl_page_assume(env, io, page);
        lu_ref_add(&page->cp_reference, "ra", cfs_current());
        cp = cl2ccc_page(cl_page_at(page, &vvp_device_type));
        if (!cp->cpg_defer_uptodate && !Page_Uptodate(vmpage)) {
                rc = cl_page_is_under_lock(env, io, page);
                if (rc == -EBUSY) {
                        cp->cpg_defer_uptodate = 1;
                        cp->cpg_ra_used = 0;
                        cl_page_list_add(queue, page);
                        rc = 1;
                } else {
                        cl_page_delete(env, page);
                        rc = -ENOLCK;
                }
        } else
                /* skip completed pages */
                cl_page_unassume(env, io, page);
        lu_ref_del(&page->cp_reference, "ra", cfs_current());
        cl_page_put(env, page);
        RETURN(rc);
}

/**
 * Initiates read-ahead of a page with given index.
 *
 * \retval     +ve: page was added to \a queue.
 *
 * \retval -ENOLCK: there is no extent lock for this part of a file, stop
 *                  read-ahead.
 *
 * \retval  -ve, 0: page wasn't added to \a queue for other reason.
 */
static int ll_read_ahead_page(const struct lu_env *env, struct cl_io *io,
                              struct cl_page_list *queue,
                              pgoff_t index, struct address_space *mapping)
{
        struct page      *vmpage;
        struct cl_object *clob  = ll_i2info(mapping->host)->lli_clob;
        struct cl_page   *page;
        enum ra_stat      which = _NR_RA_STAT; /* keep gcc happy */
        unsigned int      gfp_mask;
        int               rc    = 0;
        const char       *msg   = NULL;

        ENTRY;

        gfp_mask = GFP_HIGHUSER & ~__GFP_WAIT;
#ifdef __GFP_NOWARN
        gfp_mask |= __GFP_NOWARN;
#endif
        vmpage = grab_cache_page_nowait_gfp(mapping, index, gfp_mask);
        if (vmpage != NULL) {
                /* Check if vmpage was truncated or reclaimed */
                if (vmpage->mapping == mapping) {
                        page = cl_page_find(env, clob, vmpage->index,
                                            vmpage, CPT_CACHEABLE);
                        if (!IS_ERR(page)) {
                                rc = cl_read_ahead_page(env, io, queue,
                                                        page, vmpage);
                                if (rc == -ENOLCK) {
                                        which = RA_STAT_FAILED_MATCH;
                                        msg   = "lock match failed";
                                }
                        } else {
                                which = RA_STAT_FAILED_GRAB_PAGE;
                                msg   = "cl_page_find failed";
                        }
                } else {
                        which = RA_STAT_WRONG_GRAB_PAGE;
                        msg   = "g_c_p_n returned invalid page";
                }
                if (rc != 1)
                        unlock_page(vmpage);
                page_cache_release(vmpage);
        } else {
                which = RA_STAT_FAILED_GRAB_PAGE;
                msg   = "g_c_p_n failed";
        }
        if (msg != NULL) {
                ll_ra_stats_inc(mapping, which);
                CDEBUG(D_READA, "%s\n", msg);
        }
        RETURN(rc);
}

#define RIA_DEBUG(ria)                                                       \
        CDEBUG(D_READA, "rs %lu re %lu ro %lu rl %lu rp %lu\n",       \
        ria->ria_start, ria->ria_end, ria->ria_stoff, ria->ria_length,\
        ria->ria_pages)

#define RAS_INCREASE_STEP PTLRPC_MAX_BRW_PAGES

static inline int stride_io_mode(struct ll_readahead_state *ras)
{
        return ras->ras_consecutive_stride_requests > 1;
}
/* The function calculates how much pages will be read in
 * [off, off + length], in such stride IO area,
 * stride_offset = st_off, stride_lengh = st_len,
 * stride_pages = st_pgs
 *
 *   |------------------|*****|------------------|*****|------------|*****|....
 * st_off
 *   |--- st_pgs     ---|
 *   |-----     st_len   -----|
 *
 *              How many pages it should read in such pattern
 *              |-------------------------------------------------------------|
 *              off
 *              |<------                  length                      ------->|
 *
 *          =   |<----->|  +  |-------------------------------------| +   |---|
 *             start_left                 st_pgs * i                    end_left
 */
static unsigned long
stride_pg_count(pgoff_t st_off, unsigned long st_len, unsigned long st_pgs,
                unsigned long off, unsigned long length)
{
        __u64 start = off > st_off ? off - st_off : 0;
        __u64 end = off + length > st_off ? off + length - st_off : 0;
        unsigned long start_left = 0;
        unsigned long end_left = 0;
        unsigned long pg_count;

        if (st_len == 0 || length == 0 || end == 0)
                return length;

        start_left = do_div(start, st_len);
        if (start_left < st_pgs)
                start_left = st_pgs - start_left;
        else
                start_left = 0;

        end_left = do_div(end, st_len);
        if (end_left > st_pgs)
                end_left = st_pgs;

        CDEBUG(D_READA, "start "LPU64", end "LPU64" start_left %lu end_left %lu \n",
               start, end, start_left, end_left);

        if (start == end)
                pg_count = end_left - (st_pgs - start_left);
        else
                pg_count = start_left + st_pgs * (end - start - 1) + end_left;

        CDEBUG(D_READA, "st_off %lu, st_len %lu st_pgs %lu off %lu length %lu"
               "pgcount %lu\n", st_off, st_len, st_pgs, off, length, pg_count);

        return pg_count;
}

static int ria_page_count(struct ra_io_arg *ria)
{
        __u64 length = ria->ria_end >= ria->ria_start ?
                       ria->ria_end - ria->ria_start + 1 : 0;

        return stride_pg_count(ria->ria_stoff, ria->ria_length,
                               ria->ria_pages, ria->ria_start,
                               length);
}

/*Check whether the index is in the defined ra-window */
static int ras_inside_ra_window(unsigned long idx, struct ra_io_arg *ria)
{
        /* If ria_length == ria_pages, it means non-stride I/O mode,
         * idx should always inside read-ahead window in this case
         * For stride I/O mode, just check whether the idx is inside
         * the ria_pages. */
        return ria->ria_length == 0 || ria->ria_length == ria->ria_pages ||
               (idx >= ria->ria_stoff && (idx - ria->ria_stoff) %
                ria->ria_length < ria->ria_pages);
}

static int ll_read_ahead_pages(const struct lu_env *env,
                               struct cl_io *io, struct cl_page_list *queue,
                               struct ra_io_arg *ria,
                               unsigned long *reserved_pages,
                               struct address_space *mapping,
                               unsigned long *ra_end)
{
        int rc, count = 0, stride_ria;
        unsigned long page_idx;

        LASSERT(ria != NULL);
        RIA_DEBUG(ria);

        stride_ria = ria->ria_length > ria->ria_pages && ria->ria_pages > 0;
        for (page_idx = ria->ria_start; page_idx <= ria->ria_end &&
                        *reserved_pages > 0; page_idx++) {
                if (ras_inside_ra_window(page_idx, ria)) {
                        /* If the page is inside the read-ahead window*/
                        rc = ll_read_ahead_page(env, io, queue,
                                                page_idx, mapping);
                        if (rc == 1) {
                                (*reserved_pages)--;
                                count ++;
                        } else if (rc == -ENOLCK)
                                break;
                } else if (stride_ria) {
                        /* If it is not in the read-ahead window, and it is
                         * read-ahead mode, then check whether it should skip
                         * the stride gap */
                        pgoff_t offset;
                        /* FIXME: This assertion only is valid when it is for
                         * forward read-ahead, it will be fixed when backward
                         * read-ahead is implemented */
                        LASSERTF(page_idx > ria->ria_stoff, "Invalid page_idx %lu"
                                "rs %lu re %lu ro %lu rl %lu rp %lu\n", page_idx,
                                ria->ria_start, ria->ria_end, ria->ria_stoff,
                                ria->ria_length, ria->ria_pages);
                        offset = page_idx - ria->ria_stoff;
                        offset = offset % (ria->ria_length);
                        if (offset > ria->ria_pages) {
                                page_idx += ria->ria_length - offset;
                                CDEBUG(D_READA, "i %lu skip %lu \n", page_idx,
                                       ria->ria_length - offset);
                                continue;
                        }
                }
        }
        *ra_end = page_idx;
        return count;
}

int ll_readahead(const struct lu_env *env, struct cl_io *io,
                 struct ll_readahead_state *ras, struct address_space *mapping,
                 struct cl_page_list *queue, int flags)
{
        struct vvp_io *vio = vvp_env_io(env);
        struct vvp_thread_info *vti = vvp_env_info(env);
        struct cl_attr *attr = ccc_env_thread_attr(env);
        unsigned long start = 0, end = 0, reserved;
        unsigned long ra_end, len;
        struct inode *inode;
        struct ll_ra_read *bead;
        struct ra_io_arg *ria = &vti->vti_ria;
        struct ll_inode_info *lli;
        struct cl_object *clob;
        int ret = 0;
        __u64 kms;
        ENTRY;

        inode = mapping->host;
        lli = ll_i2info(inode);
        clob = lli->lli_clob;

        memset(ria, 0, sizeof *ria);

        cl_object_attr_lock(clob);
        ret = cl_object_attr_get(env, clob, attr);
        cl_object_attr_unlock(clob);

        if (ret != 0)
                RETURN(ret);
        kms = attr->cat_kms;
        if (kms == 0) {
                ll_ra_stats_inc(mapping, RA_STAT_ZERO_LEN);
                RETURN(0);
        }

        cfs_spin_lock(&ras->ras_lock);
        if (vio->cui_ra_window_set)
                bead = &vio->cui_bead;
        else
                bead = NULL;

        /* Enlarge the RA window to encompass the full read */
        if (bead != NULL && ras->ras_window_start + ras->ras_window_len <
            bead->lrr_start + bead->lrr_count) {
                ras->ras_window_len = bead->lrr_start + bead->lrr_count -
                                      ras->ras_window_start;
        }
        /* Reserve a part of the read-ahead window that we'll be issuing */
        if (ras->ras_window_len) {
                start = ras->ras_next_readahead;
                end = ras->ras_window_start + ras->ras_window_len - 1;
        }
        if (end != 0) {
                unsigned long tmp_end;
                /*
                 * Align RA window to an optimal boundary.
                 *
                 * XXX This would be better to align to cl_max_pages_per_rpc
                 * instead of PTLRPC_MAX_BRW_PAGES, because the RPC size may
                 * be aligned to the RAID stripe size in the future and that
                 * is more important than the RPC size.
                 */
                tmp_end = ((end + 1) & (~(PTLRPC_MAX_BRW_PAGES - 1))) - 1;
                if (tmp_end > start)
                        end = tmp_end;

                /* Truncate RA window to end of file */
                end = min(end, (unsigned long)((kms - 1) >> CFS_PAGE_SHIFT));

                ras->ras_next_readahead = max(end, end + 1);
                RAS_CDEBUG(ras);
        }
        ria->ria_start = start;
        ria->ria_end = end;
        /* If stride I/O mode is detected, get stride window*/
        if (stride_io_mode(ras)) {
                ria->ria_stoff = ras->ras_stride_offset;
                ria->ria_length = ras->ras_stride_length;
                ria->ria_pages = ras->ras_stride_pages;
        }
        cfs_spin_unlock(&ras->ras_lock);

        if (end == 0) {
                ll_ra_stats_inc(mapping, RA_STAT_ZERO_WINDOW);
                RETURN(0);
        }
        len = ria_page_count(ria);
        if (len == 0)
                RETURN(0);

        reserved = ll_ra_count_get(ll_i2sbi(inode), len);

        if (reserved < len)
                ll_ra_stats_inc(mapping, RA_STAT_MAX_IN_FLIGHT);

        CDEBUG(D_READA, "reserved page %lu \n", reserved);

        ret = ll_read_ahead_pages(env, io, queue,
                                  ria, &reserved, mapping, &ra_end);

        LASSERTF(reserved >= 0, "reserved %lu\n", reserved);
        if (reserved != 0)
                ll_ra_count_put(ll_i2sbi(inode), reserved);

        if (ra_end == end + 1 && ra_end == (kms >> CFS_PAGE_SHIFT))
                ll_ra_stats_inc(mapping, RA_STAT_EOF);

        /* if we didn't get to the end of the region we reserved from
         * the ras we need to go back and update the ras so that the
         * next read-ahead tries from where we left off.  we only do so
         * if the region we failed to issue read-ahead on is still ahead
         * of the app and behind the next index to start read-ahead from */
        CDEBUG(D_READA, "ra_end %lu end %lu stride end %lu \n",
               ra_end, end, ria->ria_end);

        if (ra_end != end + 1) {
                cfs_spin_lock(&ras->ras_lock);
                if (ra_end < ras->ras_next_readahead &&
                    index_in_window(ra_end, ras->ras_window_start, 0,
                                    ras->ras_window_len)) {
                        ras->ras_next_readahead = ra_end;
                               RAS_CDEBUG(ras);
                }
                cfs_spin_unlock(&ras->ras_lock);
        }

        RETURN(ret);
}

static void ras_set_start(struct ll_readahead_state *ras, unsigned long index)
{
        ras->ras_window_start = index & (~(RAS_INCREASE_STEP - 1));
}

/* called with the ras_lock held or from places where it doesn't matter */
static void ras_reset(struct ll_readahead_state *ras, unsigned long index)
{
        ras->ras_last_readpage = index;
        ras->ras_consecutive_requests = 0;
        ras->ras_consecutive_pages = 0;
        ras->ras_window_len = 0;
        ras_set_start(ras, index);
        ras->ras_next_readahead = max(ras->ras_window_start, index);

        RAS_CDEBUG(ras);
}

/* called with the ras_lock held or from places where it doesn't matter */
static void ras_stride_reset(struct ll_readahead_state *ras)
{
        ras->ras_consecutive_stride_requests = 0;
        ras->ras_stride_length = 0;
        ras->ras_stride_pages = 0;
        RAS_CDEBUG(ras);
}

void ll_readahead_init(struct inode *inode, struct ll_readahead_state *ras)
{
        cfs_spin_lock_init(&ras->ras_lock);
        ras_reset(ras, 0);
        ras->ras_requests = 0;
        CFS_INIT_LIST_HEAD(&ras->ras_read_beads);
}

/*
 * Check whether the read request is in the stride window.
 * If it is in the stride window, return 1, otherwise return 0.
 */
static int index_in_stride_window(unsigned long index,
                                  struct ll_readahead_state *ras,
                                  struct inode *inode)
{
        unsigned long stride_gap = index - ras->ras_last_readpage - 1;

        if (ras->ras_stride_length == 0 || ras->ras_stride_pages == 0 ||
            ras->ras_stride_pages == ras->ras_stride_length)
                return 0;

        /* If it is contiguous read */
        if (stride_gap == 0)
                return ras->ras_consecutive_pages + 1 <= ras->ras_stride_pages;

        /*Otherwise check the stride by itself */
        return (ras->ras_stride_length - ras->ras_stride_pages) == stride_gap &&
             ras->ras_consecutive_pages == ras->ras_stride_pages;
}

static void ras_update_stride_detector(struct ll_readahead_state *ras,
                                       unsigned long index)
{
        unsigned long stride_gap = index - ras->ras_last_readpage - 1;

        if (!stride_io_mode(ras) && (stride_gap != 0 ||
             ras->ras_consecutive_stride_requests == 0)) {
                ras->ras_stride_pages = ras->ras_consecutive_pages;
                ras->ras_stride_length = stride_gap +ras->ras_consecutive_pages;
        }
        LASSERT(ras->ras_request_index == 0);
        LASSERT(ras->ras_consecutive_stride_requests == 0);

        if (index <= ras->ras_last_readpage) {
                /*Reset stride window for forward read*/
                ras_stride_reset(ras);
                return;
        }

        ras->ras_stride_pages = ras->ras_consecutive_pages;
        ras->ras_stride_length = stride_gap +ras->ras_consecutive_pages;

        RAS_CDEBUG(ras);
        return;
}

static unsigned long
stride_page_count(struct ll_readahead_state *ras, unsigned long len)
{
        return stride_pg_count(ras->ras_stride_offset, ras->ras_stride_length,
                               ras->ras_stride_pages, ras->ras_stride_offset,
                               len);
}

/* Stride Read-ahead window will be increased inc_len according to
 * stride I/O pattern */
static void ras_stride_increase_window(struct ll_readahead_state *ras,
                                       struct ll_ra_info *ra,
                                       unsigned long inc_len)
{
        unsigned long left, step, window_len;
        unsigned long stride_len;

        LASSERT(ras->ras_stride_length > 0);
        LASSERTF(ras->ras_window_start + ras->ras_window_len
                 >= ras->ras_stride_offset, "window_start %lu, window_len %lu"
                 " stride_offset %lu\n", ras->ras_window_start,
                 ras->ras_window_len, ras->ras_stride_offset);

        stride_len = ras->ras_window_start + ras->ras_window_len -
                     ras->ras_stride_offset;

        left = stride_len % ras->ras_stride_length;
        window_len = ras->ras_window_len - left;

        if (left < ras->ras_stride_pages)
                left += inc_len;
        else
                left = ras->ras_stride_pages + inc_len;

        LASSERT(ras->ras_stride_pages != 0);

        step = left / ras->ras_stride_pages;
        left %= ras->ras_stride_pages;

        window_len += step * ras->ras_stride_length + left;

        if (stride_page_count(ras, window_len) <= ra->ra_max_pages_per_file)
                ras->ras_window_len = window_len;

        RAS_CDEBUG(ras);
}

static void ras_increase_window(struct ll_readahead_state *ras,
                                struct ll_ra_info *ra, struct inode *inode)
{
        /* The stretch of ra-window should be aligned with max rpc_size
         * but current clio architecture does not support retrieve such
         * information from lower layer. FIXME later
         */
        if (stride_io_mode(ras))
                ras_stride_increase_window(ras, ra, RAS_INCREASE_STEP);
        else
                ras->ras_window_len = min(ras->ras_window_len +
                                          RAS_INCREASE_STEP,
                                          ra->ra_max_pages_per_file);
}

void ras_update(struct ll_sb_info *sbi, struct inode *inode,
                struct ll_readahead_state *ras, unsigned long index,
                unsigned hit)
{
        struct ll_ra_info *ra = &sbi->ll_ra_info;
        int zero = 0, stride_detect = 0, ra_miss = 0;
        ENTRY;

        cfs_spin_lock(&ras->ras_lock);

        ll_ra_stats_inc_sbi(sbi, hit ? RA_STAT_HIT : RA_STAT_MISS);

        /* reset the read-ahead window in two cases.  First when the app seeks
         * or reads to some other part of the file.  Secondly if we get a
         * read-ahead miss that we think we've previously issued.  This can
         * be a symptom of there being so many read-ahead pages that the VM is
         * reclaiming it before we get to it. */
        if (!index_in_window(index, ras->ras_last_readpage, 8, 8)) {
                zero = 1;
                ll_ra_stats_inc_sbi(sbi, RA_STAT_DISTANT_READPAGE);
        } else if (!hit && ras->ras_window_len &&
                   index < ras->ras_next_readahead &&
                   index_in_window(index, ras->ras_window_start, 0,
                                   ras->ras_window_len)) {
                ra_miss = 1;
                ll_ra_stats_inc_sbi(sbi, RA_STAT_MISS_IN_WINDOW);
        }

        /* On the second access to a file smaller than the tunable
         * ra_max_read_ahead_whole_pages trigger RA on all pages in the
         * file up to ra_max_pages_per_file.  This is simply a best effort
         * and only occurs once per open file.  Normal RA behavior is reverted
         * to for subsequent IO.  The mmap case does not increment
         * ras_requests and thus can never trigger this behavior. */
        if (ras->ras_requests == 2 && !ras->ras_request_index) {
                __u64 kms_pages;

                kms_pages = (i_size_read(inode) + CFS_PAGE_SIZE - 1) >>
                            CFS_PAGE_SHIFT;

                CDEBUG(D_READA, "kmsp "LPU64" mwp %lu mp %lu\n", kms_pages,
                       ra->ra_max_read_ahead_whole_pages, ra->ra_max_pages_per_file);

                if (kms_pages &&
                    kms_pages <= ra->ra_max_read_ahead_whole_pages) {
                        ras->ras_window_start = 0;
                        ras->ras_last_readpage = 0;
                        ras->ras_next_readahead = 0;
                        ras->ras_window_len = min(ra->ra_max_pages_per_file,
                                ra->ra_max_read_ahead_whole_pages);
                        GOTO(out_unlock, 0);
                }
        }
        if (zero) {
                /* check whether it is in stride I/O mode*/
                if (!index_in_stride_window(index, ras, inode)) {
                        if (ras->ras_consecutive_stride_requests == 0 &&
                            ras->ras_request_index == 0) {
                                ras_update_stride_detector(ras, index);
                                ras->ras_consecutive_stride_requests ++;
                        } else {
                                ras_stride_reset(ras);
                        }
                        ras_reset(ras, index);
                        ras->ras_consecutive_pages++;
                        GOTO(out_unlock, 0);
                } else {
                        ras->ras_consecutive_pages = 0;
                        ras->ras_consecutive_requests = 0;
                        if (++ras->ras_consecutive_stride_requests > 1)
                                stride_detect = 1;
                        RAS_CDEBUG(ras);
                }
        } else {
                if (ra_miss) {
                        if (index_in_stride_window(index, ras, inode) &&
                            stride_io_mode(ras)) {
                                /*If stride-RA hit cache miss, the stride dector
                                 *will not be reset to avoid the overhead of
                                 *redetecting read-ahead mode */
                                if (index != ras->ras_last_readpage + 1)
                                       ras->ras_consecutive_pages = 0;
                                ras_reset(ras, index);
                                RAS_CDEBUG(ras);
                        } else {
                                /* Reset both stride window and normal RA
                                 * window */
                                ras_reset(ras, index);
                                ras->ras_consecutive_pages++;
                                ras_stride_reset(ras);
                                GOTO(out_unlock, 0);
                        }
                } else if (stride_io_mode(ras)) {
                        /* If this is contiguous read but in stride I/O mode
                         * currently, check whether stride step still is valid,
                         * if invalid, it will reset the stride ra window*/
                        if (!index_in_stride_window(index, ras, inode)) {
                                /* Shrink stride read-ahead window to be zero */
                                ras_stride_reset(ras);
                                ras->ras_window_len = 0;
                                ras->ras_next_readahead = index;
                        }
                }
        }
        ras->ras_consecutive_pages++;
        ras->ras_last_readpage = index;
        ras_set_start(ras, index);

        if (stride_io_mode(ras))
                /* Since stride readahead is sentivite to the offset
                 * of read-ahead, so we use original offset here,
                 * instead of ras_window_start, which is 1M aligned*/
                ras->ras_next_readahead = max(index,
                                              ras->ras_next_readahead);
        else
                ras->ras_next_readahead = max(ras->ras_window_start,
                                              ras->ras_next_readahead);
        RAS_CDEBUG(ras);

        /* Trigger RA in the mmap case where ras_consecutive_requests
         * is not incremented and thus can't be used to trigger RA */
        if (!ras->ras_window_len && ras->ras_consecutive_pages == 4) {
                ras->ras_window_len = RAS_INCREASE_STEP;
                GOTO(out_unlock, 0);
        }

        /* Initially reset the stride window offset to next_readahead*/
        if (ras->ras_consecutive_stride_requests == 2 && stride_detect) {
                /**
                 * Once stride IO mode is detected, next_readahead should be
                 * reset to make sure next_readahead > stride offset
                 */
                ras->ras_next_readahead = max(index, ras->ras_next_readahead);
                ras->ras_stride_offset = index;
                ras->ras_window_len = RAS_INCREASE_STEP;
        }

        /* The initial ras_window_len is set to the request size.  To avoid
         * uselessly reading and discarding pages for random IO the window is
         * only increased once per consecutive request received. */
        if ((ras->ras_consecutive_requests > 1 || stride_detect) &&
            !ras->ras_request_index)
                ras_increase_window(ras, ra, inode);
        EXIT;
out_unlock:
        RAS_CDEBUG(ras);
        ras->ras_request_index++;
        cfs_spin_unlock(&ras->ras_lock);
        return;
}

int ll_writepage(struct page *vmpage, struct writeback_control *unused)
{
        struct inode           *inode = vmpage->mapping->host;
        struct lu_env          *env;
        struct cl_io           *io;
        struct cl_page         *page;
        struct cl_object       *clob;
        struct cl_2queue       *queue;
        struct cl_env_nest      nest;
        int result;
        ENTRY;

        LASSERT(PageLocked(vmpage));
        LASSERT(!PageWriteback(vmpage));

        if (ll_i2dtexp(inode) == NULL)
                RETURN(-EINVAL);

        env = cl_env_nested_get(&nest);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        queue = &vvp_env_info(env)->vti_queue;
        clob  = ll_i2info(inode)->lli_clob;
        LASSERT(clob != NULL);

        io = ccc_env_thread_io(env);
        io->ci_obj = clob;
        result = cl_io_init(env, io, CIT_MISC, clob);
        if (result == 0) {
                page = cl_page_find(env, clob, vmpage->index,
                                    vmpage, CPT_CACHEABLE);
                if (!IS_ERR(page)) {
                        lu_ref_add(&page->cp_reference, "writepage",
                                   cfs_current());
                        cl_page_assume(env, io, page);
                        /*
                         * Mark page dirty, because this is what
                         * ->vio_submit()->cpo_prep_write() assumes.
                         *
                         * XXX better solution is to detect this from within
                         * cl_io_submit_rw() somehow.
                         */
                        set_page_dirty(vmpage);
                        cl_2queue_init_page(queue, page);
                        result = cl_io_submit_rw(env, io, CRT_WRITE,
                                                 queue, CRP_NORMAL);
                        cl_page_list_disown(env, io, &queue->c2_qin);
                        if (result != 0) {
                                /*
                                 * There is no need to clear PG_writeback, as
                                 * cl_io_submit_rw() calls completion callback
                                 * on failure.
                                 */
                                /*
                                 * Re-dirty page on error so it retries write,
                                 * but not in case when IO has actually
                                 * occurred and completed with an error.
                                 */
                                if (!PageError(vmpage))
                                        set_page_dirty(vmpage);
                        }
                        LASSERT(!cl_page_is_owned(page, io));
                        lu_ref_del(&page->cp_reference,
                                   "writepage", cfs_current());
                        cl_page_put(env, page);
                        cl_2queue_fini(env, queue);
                }
        }
        cl_io_fini(env, io);
        cl_env_nested_put(&nest, env);
        RETURN(result);
}

int ll_readpage(struct file *file, struct page *vmpage)
{
        struct ll_cl_context *lcc;
        int result;
        ENTRY;

        lcc = ll_cl_init(file, vmpage, 0);
        if (!IS_ERR(lcc)) {
                struct lu_env  *env  = lcc->lcc_env;
                struct cl_io   *io   = lcc->lcc_io;
                struct cl_page *page = lcc->lcc_page;

                LASSERT(page->cp_type == CPT_CACHEABLE);
                if (likely(!PageUptodate(vmpage))) {
                        cl_page_assume(env, io, page);
                        result = cl_io_read_page(env, io, page);
                } else {
                        /* Page from a non-object file. */
                        LASSERT(!ll_i2info(vmpage->mapping->host)->lli_smd);
                        unlock_page(vmpage);
                        result = 0;
                }
                ll_cl_fini(lcc);
        } else {
                unlock_page(vmpage);
                result = PTR_ERR(lcc);
        }
        RETURN(result);
}

