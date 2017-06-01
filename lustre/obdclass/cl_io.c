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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Client IO.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/sched.h>
#include <linux/list.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include <cl_object.h>
#include "cl_internal.h"
#include <lustre_compat.h>

/*****************************************************************************
 *
 * cl_io interface.
 *
 */

static inline int cl_io_type_is_valid(enum cl_io_type type)
{
        return CIT_READ <= type && type < CIT_OP_NR;
}

static inline int cl_io_is_loopable(const struct cl_io *io)
{
        return cl_io_type_is_valid(io->ci_type) && io->ci_type != CIT_MISC;
}

/**
 * cl_io invariant that holds at all times when exported cl_io_*() functions
 * are entered and left.
 */
static int cl_io_invariant(const struct cl_io *io)
{
        struct cl_io *up;

        up = io->ci_parent;
        return
                /*
                 * io can own pages only when it is ongoing. Sub-io might
                 * still be in CIS_LOCKED state when top-io is in
                 * CIS_IO_GOING.
                 */
                ergo(io->ci_owned_nr > 0, io->ci_state == CIS_IO_GOING ||
                     (io->ci_state == CIS_LOCKED && up != NULL));
}

/**
 * Finalize \a io, by calling cl_io_operations::cio_fini() bottom-to-top.
 */
void cl_io_fini(const struct lu_env *env, struct cl_io *io)
{
	struct cl_io_slice    *slice;

        LINVRNT(cl_io_type_is_valid(io->ci_type));
        LINVRNT(cl_io_invariant(io));
        ENTRY;

	while (!list_empty(&io->ci_layers)) {
                slice = container_of(io->ci_layers.prev, struct cl_io_slice,
                                     cis_linkage);
		list_del_init(&slice->cis_linkage);
                if (slice->cis_iop->op[io->ci_type].cio_fini != NULL)
                        slice->cis_iop->op[io->ci_type].cio_fini(env, slice);
                /*
                 * Invalidate slice to catch use after free. This assumes that
                 * slices are allocated within session and can be touched
                 * after ->cio_fini() returns.
                 */
                slice->cis_io = NULL;
        }
        io->ci_state = CIS_FINI;

	/* sanity check for layout change */
	switch(io->ci_type) {
	case CIT_READ:
	case CIT_WRITE:
	case CIT_DATA_VERSION:
	case CIT_FAULT:
		break;
	case CIT_FSYNC:
		LASSERT(!io->ci_need_restart);
		break;
	case CIT_SETATTR:
	case CIT_MISC:
		/* Check ignore layout change conf */
		LASSERT(ergo(io->ci_ignore_layout || !io->ci_verify_layout,
				!io->ci_need_restart));
		break;
	case CIT_LADVISE:
		break;
	default:
		LBUG();
	}
	EXIT;
}
EXPORT_SYMBOL(cl_io_fini);

static int cl_io_init0(const struct lu_env *env, struct cl_io *io,
                       enum cl_io_type iot, struct cl_object *obj)
{
        struct cl_object *scan;
        int result;

        LINVRNT(io->ci_state == CIS_ZERO || io->ci_state == CIS_FINI);
        LINVRNT(cl_io_type_is_valid(iot));
        LINVRNT(cl_io_invariant(io));
        ENTRY;

        io->ci_type = iot;
	INIT_LIST_HEAD(&io->ci_lockset.cls_todo);
	INIT_LIST_HEAD(&io->ci_lockset.cls_done);
	INIT_LIST_HEAD(&io->ci_layers);

        result = 0;
        cl_object_for_each(scan, obj) {
                if (scan->co_ops->coo_io_init != NULL) {
                        result = scan->co_ops->coo_io_init(env, scan, io);
                        if (result != 0)
                                break;
                }
        }
        if (result == 0)
                io->ci_state = CIS_INIT;
        RETURN(result);
}

/**
 * Initialize sub-io, by calling cl_io_operations::cio_init() top-to-bottom.
 *
 * \pre obj != cl_object_top(obj)
 */
int cl_io_sub_init(const struct lu_env *env, struct cl_io *io,
                   enum cl_io_type iot, struct cl_object *obj)
{
        LASSERT(obj != cl_object_top(obj));

        return cl_io_init0(env, io, iot, obj);
}
EXPORT_SYMBOL(cl_io_sub_init);

/**
 * Initialize \a io, by calling cl_io_operations::cio_init() top-to-bottom.
 *
 * Caller has to call cl_io_fini() after a call to cl_io_init(), no matter
 * what the latter returned.
 *
 * \pre obj == cl_object_top(obj)
 * \pre cl_io_type_is_valid(iot)
 * \post cl_io_type_is_valid(io->ci_type) && io->ci_type == iot
 */
int cl_io_init(const struct lu_env *env, struct cl_io *io,
               enum cl_io_type iot, struct cl_object *obj)
{
        LASSERT(obj == cl_object_top(obj));

        return cl_io_init0(env, io, iot, obj);
}
EXPORT_SYMBOL(cl_io_init);

/**
 * Initialize read or write io.
 *
 * \pre iot == CIT_READ || iot == CIT_WRITE
 */
int cl_io_rw_init(const struct lu_env *env, struct cl_io *io,
                  enum cl_io_type iot, loff_t pos, size_t count)
{
	LINVRNT(iot == CIT_READ || iot == CIT_WRITE);
	LINVRNT(io->ci_obj != NULL);
	ENTRY;

	if (cfs_ptengine_weight(cl_io_engine) < 2)
		io->ci_pio = 0;

	LU_OBJECT_HEADER(D_VFSTRACE, env, &io->ci_obj->co_lu,
			 "io %s range: [%llu, %llu) %s %s %s %s\n",
			 iot == CIT_READ ? "read" : "write",
			 pos, pos + count,
			 io->u.ci_rw.rw_nonblock ? "nonblock" : "block",
			 io->u.ci_rw.rw_append ? "append" : "-",
			 io->u.ci_rw.rw_sync ? "sync" : "-",
			 io->ci_pio ? "pio" : "-");

	io->u.ci_rw.rw_range.cir_pos   = pos;
	io->u.ci_rw.rw_range.cir_count = count;

	RETURN(cl_io_init(env, io, iot, io->ci_obj));
}
EXPORT_SYMBOL(cl_io_rw_init);

static int cl_lock_descr_sort(const struct cl_lock_descr *d0,
                              const struct cl_lock_descr *d1)
{
	return lu_fid_cmp(lu_object_fid(&d0->cld_obj->co_lu),
			  lu_object_fid(&d1->cld_obj->co_lu));
}

/*
 * Sort locks in lexicographical order of their (fid, start-offset) pairs.
 */
static void cl_io_locks_sort(struct cl_io *io)
{
        int done = 0;

        ENTRY;
        /* hidden treasure: bubble sort for now. */
        do {
                struct cl_io_lock_link *curr;
                struct cl_io_lock_link *prev;
                struct cl_io_lock_link *temp;

                done = 1;
                prev = NULL;

		list_for_each_entry_safe(curr, temp, &io->ci_lockset.cls_todo,
					 cill_linkage) {
			if (prev != NULL) {
				switch (cl_lock_descr_sort(&prev->cill_descr,
							   &curr->cill_descr)) {
				case 0:
					/*
					 * IMPOSSIBLE:	Identical locks are
					 *		already removed at
					 *		this point.
					 */
				default:
					LBUG();
				case +1:
					list_move_tail(&curr->cill_linkage,
						       &prev->cill_linkage);
					done = 0;
					continue; /* don't change prev: it's
						   * still "previous" */
				case -1: /* already in order */
					break;
				}
			}
			prev = curr;
		}
	} while (!done);
	EXIT;
}

static void cl_lock_descr_merge(struct cl_lock_descr *d0,
				const struct cl_lock_descr *d1)
{
	d0->cld_start = min(d0->cld_start, d1->cld_start);
	d0->cld_end = max(d0->cld_end, d1->cld_end);

	if (d1->cld_mode == CLM_WRITE && d0->cld_mode != CLM_WRITE)
		d0->cld_mode = CLM_WRITE;

	if (d1->cld_mode == CLM_GROUP && d0->cld_mode != CLM_GROUP)
		d0->cld_mode = CLM_GROUP;
}

static int cl_lockset_merge(const struct cl_lockset *set,
			    const struct cl_lock_descr *need)
{
	struct cl_io_lock_link *scan;

	ENTRY;
	list_for_each_entry(scan, &set->cls_todo, cill_linkage) {
		if (!cl_object_same(scan->cill_descr.cld_obj, need->cld_obj))
			continue;

		/* Merge locks for the same object because ldlm lock server
		 * may expand the lock extent, otherwise there is a deadlock
		 * case if two conflicted locks are queueud for the same object
		 * and lock server expands one lock to overlap the another.
		 * The side effect is that it can generate a multi-stripe lock
		 * that may cause casacading problem */
		cl_lock_descr_merge(&scan->cill_descr, need);
		CDEBUG(D_VFSTRACE, "lock: %d: [%lu, %lu]\n",
		       scan->cill_descr.cld_mode, scan->cill_descr.cld_start,
		       scan->cill_descr.cld_end);
		RETURN(+1);
	}
	RETURN(0);
}

static int cl_lockset_lock(const struct lu_env *env, struct cl_io *io,
			   struct cl_lockset *set)
{
	struct cl_io_lock_link *link;
	struct cl_io_lock_link *temp;
	int result;

	ENTRY;
	result = 0;
	list_for_each_entry_safe(link, temp, &set->cls_todo, cill_linkage) {
		result = cl_lock_request(env, io, &link->cill_lock);
		if (result < 0)
			break;

		list_move(&link->cill_linkage, &set->cls_done);
	}
	RETURN(result);
}

/**
 * Takes locks necessary for the current iteration of io.
 *
 * Calls cl_io_operations::cio_lock() top-to-bottom to collect locks required
 * by layers for the current iteration. Then sort locks (to avoid dead-locks),
 * and acquire them.
 */
int cl_io_lock(const struct lu_env *env, struct cl_io *io)
{
        const struct cl_io_slice *scan;
        int result = 0;

        LINVRNT(cl_io_is_loopable(io));
        LINVRNT(io->ci_state == CIS_IT_STARTED);
        LINVRNT(cl_io_invariant(io));

        ENTRY;
	list_for_each_entry(scan, &io->ci_layers, cis_linkage) {
		if (scan->cis_iop->op[io->ci_type].cio_lock == NULL)
			continue;
		result = scan->cis_iop->op[io->ci_type].cio_lock(env, scan);
		if (result != 0)
			break;
	}
        if (result == 0) {
                cl_io_locks_sort(io);
                result = cl_lockset_lock(env, io, &io->ci_lockset);
        }
        if (result != 0)
                cl_io_unlock(env, io);
        else
                io->ci_state = CIS_LOCKED;
        RETURN(result);
}
EXPORT_SYMBOL(cl_io_lock);

/**
 * Release locks takes by io.
 */
void cl_io_unlock(const struct lu_env *env, struct cl_io *io)
{
        struct cl_lockset        *set;
        struct cl_io_lock_link   *link;
        struct cl_io_lock_link   *temp;
        const struct cl_io_slice *scan;

        LASSERT(cl_io_is_loopable(io));
        LASSERT(CIS_IT_STARTED <= io->ci_state && io->ci_state < CIS_UNLOCKED);
        LINVRNT(cl_io_invariant(io));

        ENTRY;
        set = &io->ci_lockset;

	list_for_each_entry_safe(link, temp, &set->cls_todo, cill_linkage) {
		list_del_init(&link->cill_linkage);
		if (link->cill_fini != NULL)
			link->cill_fini(env, link);
	}

	list_for_each_entry_safe(link, temp, &set->cls_done, cill_linkage) {
		list_del_init(&link->cill_linkage);
		cl_lock_release(env, &link->cill_lock);
		if (link->cill_fini != NULL)
			link->cill_fini(env, link);
	}

	list_for_each_entry_reverse(scan, &io->ci_layers, cis_linkage) {
		if (scan->cis_iop->op[io->ci_type].cio_unlock != NULL)
			scan->cis_iop->op[io->ci_type].cio_unlock(env, scan);
	}
	io->ci_state = CIS_UNLOCKED;
	EXIT;
}
EXPORT_SYMBOL(cl_io_unlock);

/**
 * Prepares next iteration of io.
 *
 * Calls cl_io_operations::cio_iter_init() top-to-bottom. This exists to give
 * layers a chance to modify io parameters, e.g., so that lov can restrict io
 * to a single stripe.
 */
int cl_io_iter_init(const struct lu_env *env, struct cl_io *io)
{
        const struct cl_io_slice *scan;
        int result;

        LINVRNT(cl_io_is_loopable(io));
        LINVRNT(io->ci_state == CIS_INIT || io->ci_state == CIS_IT_ENDED);
        LINVRNT(cl_io_invariant(io));

        ENTRY;
        result = 0;
	list_for_each_entry(scan, &io->ci_layers, cis_linkage) {
		if (scan->cis_iop->op[io->ci_type].cio_iter_init == NULL)
			continue;
		result = scan->cis_iop->op[io->ci_type].cio_iter_init(env,
								      scan);
		if (result != 0)
			break;
	}
        if (result == 0)
                io->ci_state = CIS_IT_STARTED;
        RETURN(result);
}
EXPORT_SYMBOL(cl_io_iter_init);

/**
 * Finalizes io iteration.
 *
 * Calls cl_io_operations::cio_iter_fini() bottom-to-top.
 */
void cl_io_iter_fini(const struct lu_env *env, struct cl_io *io)
{
        const struct cl_io_slice *scan;

        LINVRNT(cl_io_is_loopable(io));
        LINVRNT(io->ci_state == CIS_UNLOCKED);
        LINVRNT(cl_io_invariant(io));

        ENTRY;
	list_for_each_entry_reverse(scan, &io->ci_layers, cis_linkage) {
		if (scan->cis_iop->op[io->ci_type].cio_iter_fini != NULL)
			scan->cis_iop->op[io->ci_type].cio_iter_fini(env, scan);
	}
        io->ci_state = CIS_IT_ENDED;
        EXIT;
}
EXPORT_SYMBOL(cl_io_iter_fini);

/**
 * Records that read or write io progressed \a nob bytes forward.
 */
void cl_io_rw_advance(const struct lu_env *env, struct cl_io *io, size_t nob)
{
        const struct cl_io_slice *scan;

        LINVRNT(io->ci_type == CIT_READ || io->ci_type == CIT_WRITE ||
                nob == 0);
        LINVRNT(cl_io_is_loopable(io));
        LINVRNT(cl_io_invariant(io));

        ENTRY;

	io->u.ci_rw.rw_range.cir_pos   += nob;
	io->u.ci_rw.rw_range.cir_count -= nob;

        /* layers have to be notified. */
	list_for_each_entry_reverse(scan, &io->ci_layers, cis_linkage) {
		if (scan->cis_iop->op[io->ci_type].cio_advance != NULL)
			scan->cis_iop->op[io->ci_type].cio_advance(env, scan,
								   nob);
	}
        EXIT;
}

/**
 * Adds a lock to a lockset.
 */
int cl_io_lock_add(const struct lu_env *env, struct cl_io *io,
                   struct cl_io_lock_link *link)
{
        int result;

        ENTRY;
        if (cl_lockset_merge(&io->ci_lockset, &link->cill_descr))
                result = +1;
        else {
		list_add(&link->cill_linkage, &io->ci_lockset.cls_todo);
                result = 0;
        }
        RETURN(result);
}
EXPORT_SYMBOL(cl_io_lock_add);

static void cl_free_io_lock_link(const struct lu_env *env,
                                 struct cl_io_lock_link *link)
{
        OBD_FREE_PTR(link);
}

/**
 * Allocates new lock link, and uses it to add a lock to a lockset.
 */
int cl_io_lock_alloc_add(const struct lu_env *env, struct cl_io *io,
                         struct cl_lock_descr *descr)
{
	struct cl_io_lock_link *link;
	int result;

	ENTRY;
	OBD_ALLOC_PTR(link);
	if (link != NULL) {
		link->cill_descr = *descr;
		link->cill_fini  = cl_free_io_lock_link;
		result = cl_io_lock_add(env, io, link);
		if (result) /* lock match */
			link->cill_fini(env, link);
	} else
		result = -ENOMEM;

	RETURN(result);
}
EXPORT_SYMBOL(cl_io_lock_alloc_add);

/**
 * Starts io by calling cl_io_operations::cio_start() top-to-bottom.
 */
int cl_io_start(const struct lu_env *env, struct cl_io *io)
{
        const struct cl_io_slice *scan;
        int result = 0;

        LINVRNT(cl_io_is_loopable(io));
        LINVRNT(io->ci_state == CIS_LOCKED);
        LINVRNT(cl_io_invariant(io));
        ENTRY;

        io->ci_state = CIS_IO_GOING;
	list_for_each_entry(scan, &io->ci_layers, cis_linkage) {
		if (scan->cis_iop->op[io->ci_type].cio_start == NULL)
			continue;
		result = scan->cis_iop->op[io->ci_type].cio_start(env, scan);
		if (result != 0)
			break;
	}
        if (result >= 0)
                result = 0;
        RETURN(result);
}
EXPORT_SYMBOL(cl_io_start);

/**
 * Wait until current io iteration is finished by calling
 * cl_io_operations::cio_end() bottom-to-top.
 */
void cl_io_end(const struct lu_env *env, struct cl_io *io)
{
        const struct cl_io_slice *scan;

        LINVRNT(cl_io_is_loopable(io));
        LINVRNT(io->ci_state == CIS_IO_GOING);
        LINVRNT(cl_io_invariant(io));
        ENTRY;

	list_for_each_entry_reverse(scan, &io->ci_layers, cis_linkage) {
		if (scan->cis_iop->op[io->ci_type].cio_end != NULL)
			scan->cis_iop->op[io->ci_type].cio_end(env, scan);
		/* TODO: error handling. */
	}
        io->ci_state = CIS_IO_FINISHED;
        EXIT;
}
EXPORT_SYMBOL(cl_io_end);

/**
 * Called by read io, to decide the readahead extent
 *
 * \see cl_io_operations::cio_read_ahead()
 */
int cl_io_read_ahead(const struct lu_env *env, struct cl_io *io,
		     pgoff_t start, struct cl_read_ahead *ra)
{
	const struct cl_io_slice *scan;
	int                       result = 0;

	LINVRNT(io->ci_type == CIT_READ || io->ci_type == CIT_FAULT);
	LINVRNT(io->ci_state == CIS_IO_GOING || io->ci_state == CIS_LOCKED);
	LINVRNT(cl_io_invariant(io));
	ENTRY;

	list_for_each_entry(scan, &io->ci_layers, cis_linkage) {
		if (scan->cis_iop->cio_read_ahead == NULL)
			continue;

		result = scan->cis_iop->cio_read_ahead(env, scan, start, ra);
		if (result != 0)
			break;
	}
	RETURN(result > 0 ? 0 : result);
}
EXPORT_SYMBOL(cl_io_read_ahead);

/**
 * Commit a list of contiguous pages into writeback cache.
 *
 * \returns 0 if all pages committed, or errcode if error occurred.
 * \see cl_io_operations::cio_commit_async()
 */
int cl_io_commit_async(const struct lu_env *env, struct cl_io *io,
			struct cl_page_list *queue, int from, int to,
			cl_commit_cbt cb)
{
	const struct cl_io_slice *scan;
	int result = 0;
	ENTRY;

	list_for_each_entry(scan, &io->ci_layers, cis_linkage) {
		if (scan->cis_iop->cio_commit_async == NULL)
			continue;
		result = scan->cis_iop->cio_commit_async(env, scan, queue,
							 from, to, cb);
		if (result != 0)
			break;
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_io_commit_async);

/**
 * Submits a list of pages for immediate io.
 *
 * After the function gets returned, The submitted pages are moved to
 * queue->c2_qout queue, and queue->c2_qin contain both the pages don't need
 * to be submitted, and the pages are errant to submit.
 *
 * \returns 0 if at least one page was submitted, error code otherwise.
 * \see cl_io_operations::cio_submit()
 */
int cl_io_submit_rw(const struct lu_env *env, struct cl_io *io,
		    enum cl_req_type crt, struct cl_2queue *queue)
{
	const struct cl_io_slice *scan;
	int result = 0;
	ENTRY;

	list_for_each_entry(scan, &io->ci_layers, cis_linkage) {
		if (scan->cis_iop->cio_submit == NULL)
			continue;
		result = scan->cis_iop->cio_submit(env, scan, crt, queue);
		if (result != 0)
			break;
	}
	/*
	 * If ->cio_submit() failed, no pages were sent.
	 */
	LASSERT(ergo(result != 0, list_empty(&queue->c2_qout.pl_pages)));
	RETURN(result);
}
EXPORT_SYMBOL(cl_io_submit_rw);

/**
 * Submit a sync_io and wait for the IO to be finished, or error happens.
 * If \a timeout is zero, it means to wait for the IO unconditionally.
 */
int cl_io_submit_sync(const struct lu_env *env, struct cl_io *io,
		      enum cl_req_type iot, struct cl_2queue *queue,
		      long timeout)
{
	struct cl_sync_io *anchor = &cl_env_info(env)->clt_anchor;
	struct cl_page *pg;
	int rc;

	cl_page_list_for_each(pg, &queue->c2_qin) {
		LASSERT(pg->cp_sync_io == NULL);
		pg->cp_sync_io = anchor;
	}

	cl_sync_io_init(anchor, queue->c2_qin.pl_nr, &cl_sync_io_end);
	rc = cl_io_submit_rw(env, io, iot, queue);
	if (rc == 0) {
		/*
		 * If some pages weren't sent for any reason (e.g.,
		 * read found up-to-date pages in the cache, or write found
		 * clean pages), count them as completed to avoid infinite
		 * wait.
		 */
		cl_page_list_for_each(pg, &queue->c2_qin) {
			pg->cp_sync_io = NULL;
			cl_sync_io_note(env, anchor, 1);
		}

		/* wait for the IO to be finished. */
		rc = cl_sync_io_wait(env, anchor, timeout);
		cl_page_list_assume(env, io, &queue->c2_qout);
	} else {
		LASSERT(list_empty(&queue->c2_qout.pl_pages));
		cl_page_list_for_each(pg, &queue->c2_qin)
			pg->cp_sync_io = NULL;
	}
	return rc;
}
EXPORT_SYMBOL(cl_io_submit_sync);

/**
 * Cancel an IO which has been submitted by cl_io_submit_rw.
 */
int cl_io_cancel(const struct lu_env *env, struct cl_io *io,
                 struct cl_page_list *queue)
{
        struct cl_page *page;
        int result = 0;

        CERROR("Canceling ongoing page trasmission\n");
        cl_page_list_for_each(page, queue) {
                int rc;

                rc = cl_page_cancel(env, page);
                result = result ?: rc;
        }
        return result;
}

static
struct cl_io_pt *cl_io_submit_pt(struct cl_io *io, loff_t pos, size_t count)
{
	struct cl_io_pt *pt;
	int rc;

	OBD_ALLOC(pt, sizeof(*pt));
	if (pt == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	pt->cip_next = NULL;
	init_sync_kiocb(&pt->cip_iocb, io->u.ci_rw.rw_file);
	pt->cip_iocb.ki_pos = pos;
#ifdef HAVE_KIOCB_KI_LEFT
	pt->cip_iocb.ki_left = count;
#elif defined(HAVE_KI_NBYTES)
	pt->cip_iocb.ki_nbytes = count;
#endif
	pt->cip_iter = io->u.ci_rw.rw_iter;
	iov_iter_truncate(&pt->cip_iter, count);
	pt->cip_file   = io->u.ci_rw.rw_file;
	pt->cip_iot    = io->ci_type;
	pt->cip_pos    = pos;
	pt->cip_count  = count;
	pt->cip_result = 0;

	rc = cfs_ptask_init(&pt->cip_task, io->u.ci_rw.rw_ptask, pt,
			    PTF_ORDERED | PTF_COMPLETE |
			    PTF_USER_MM | PTF_RETRY, smp_processor_id());
	if (rc)
		GOTO(out_error, rc);

	CDEBUG(D_VFSTRACE, "submit %s range: [%llu, %llu)\n",
		io->ci_type == CIT_READ ? "read" : "write",
		pos, pos + count);

	rc = cfs_ptask_submit(&pt->cip_task, cl_io_engine);
	if (rc)
		GOTO(out_error, rc);

	RETURN(pt);

out_error:
	OBD_FREE(pt, sizeof(*pt));
	RETURN(ERR_PTR(rc));
}

/**
 * Main io loop.
 *
 * Pumps io through iterations calling
 *
 *    - cl_io_iter_init()
 *
 *    - cl_io_lock()
 *
 *    - cl_io_start()
 *
 *    - cl_io_end()
 *
 *    - cl_io_unlock()
 *
 *    - cl_io_iter_fini()
 *
 * repeatedly until there is no more io to do.
 */
int cl_io_loop(const struct lu_env *env, struct cl_io *io)
{
	struct cl_io_pt *pt = NULL, *head = NULL;
	struct cl_io_pt **tail = &head;
	loff_t pos;
	size_t count;
	size_t last_chunk_count = 0;
	bool short_io = false;
	int rc = 0;
	ENTRY;

	LINVRNT(cl_io_is_loopable(io));

	do {
		io->ci_continue = 0;

		rc = cl_io_iter_init(env, io);
		if (rc) {
			cl_io_iter_fini(env, io);
			break;
		}

		pos   = io->u.ci_rw.rw_range.cir_pos;
		count = io->u.ci_rw.rw_range.cir_count;

		if (io->ci_pio) {
			/* submit this range for parallel execution */
			pt = cl_io_submit_pt(io, pos, count);
			if (IS_ERR(pt)) {
				cl_io_iter_fini(env, io);
				rc = PTR_ERR(pt);
				break;
			}

			*tail = pt;
			tail = &pt->cip_next;
		} else {
			size_t nob = io->ci_nob;

			CDEBUG(D_VFSTRACE,
				"execute type %u range: [%llu, %llu) nob: %zu %s\n",
				io->ci_type, pos, pos + count, nob,
				io->ci_continue ? "continue" : "stop");

			rc = cl_io_lock(env, io);
			if (rc) {
				cl_io_iter_fini(env, io);
				break;
			}

			/*
			 * Notify layers that locks has been taken,
			 * and do actual i/o.
			 *
			 *   - llite: kms, short read;
			 *   - llite: generic_file_read();
			 */
			rc = cl_io_start(env, io);

			/*
			 * Send any remaining pending
			 * io, etc.
			 *
			 *   - llite: ll_rw_stats_tally.
			 */
			cl_io_end(env, io);
			cl_io_unlock(env, io);

			count = io->ci_nob - nob;
			last_chunk_count = count;
		}

		cl_io_rw_advance(env, io, count);
		cl_io_iter_fini(env, io);
	} while (!rc && io->ci_continue);

	CDEBUG(D_VFSTRACE, "loop type %u done: nob: %zu, rc: %d %s\n",
		io->ci_type, io->ci_nob, rc,
		io->ci_continue ? "continue" : "stop");

	while (head != NULL) {
		int rc2;

		pt = head;
		head = head->cip_next;

		rc2 = cfs_ptask_wait_for(&pt->cip_task);
		LASSERTF(!rc2, "wait for task error: %d\n", rc2);

		rc2 = cfs_ptask_result(&pt->cip_task);
		CDEBUG(D_VFSTRACE,
			"done %s range: [%llu, %llu) ret: %zd, rc: %d\n",
			pt->cip_iot == CIT_READ ? "read" : "write",
			pt->cip_pos, pt->cip_pos + pt->cip_count,
			pt->cip_result, rc2);
		if (rc2)
			rc = rc ? rc : rc2;
		if (!short_io) {
			if (!rc2) /* IO is done by this task successfully */
				io->ci_nob += pt->cip_result;
			if (pt->cip_result < pt->cip_count) {
				/* short IO happened.
				 * Not necessary to be an error */
				CDEBUG(D_VFSTRACE,
					"incomplete range: [%llu, %llu) "
					"last_chunk_count: %zu\n",
					pt->cip_pos,
					pt->cip_pos + pt->cip_count,
					last_chunk_count);
				io->ci_nob -= last_chunk_count;
				short_io = true;
			}
		}
		OBD_FREE(pt, sizeof(*pt));
	}

	CDEBUG(D_VFSTRACE, "return nob: %zu (%s io), rc: %d\n",
		io->ci_nob, short_io ? "short" : "full", rc);

	RETURN(rc < 0 ? rc : io->ci_result);
}
EXPORT_SYMBOL(cl_io_loop);

/**
 * Adds io slice to the cl_io.
 *
 * This is called by cl_object_operations::coo_io_init() methods to add a
 * per-layer state to the io. New state is added at the end of
 * cl_io::ci_layers list, that is, it is at the bottom of the stack.
 *
 * \see cl_lock_slice_add(), cl_req_slice_add(), cl_page_slice_add()
 */
void cl_io_slice_add(struct cl_io *io, struct cl_io_slice *slice,
                     struct cl_object *obj,
                     const struct cl_io_operations *ops)
{
	struct list_head *linkage = &slice->cis_linkage;

        LASSERT((linkage->prev == NULL && linkage->next == NULL) ||
		list_empty(linkage));
        ENTRY;

	list_add_tail(linkage, &io->ci_layers);
        slice->cis_io  = io;
        slice->cis_obj = obj;
        slice->cis_iop = ops;
        EXIT;
}
EXPORT_SYMBOL(cl_io_slice_add);


/**
 * Initializes page list.
 */
void cl_page_list_init(struct cl_page_list *plist)
{
	ENTRY;
	plist->pl_nr = 0;
	INIT_LIST_HEAD(&plist->pl_pages);
	plist->pl_owner = current;
	EXIT;
}
EXPORT_SYMBOL(cl_page_list_init);

/**
 * Adds a page to a page list.
 */
void cl_page_list_add(struct cl_page_list *plist, struct cl_page *page)
{
	ENTRY;
	/* it would be better to check that page is owned by "current" io, but
	 * it is not passed here. */
	LASSERT(page->cp_owner != NULL);
	LINVRNT(plist->pl_owner == current);

	LASSERT(list_empty(&page->cp_batch));
	list_add_tail(&page->cp_batch, &plist->pl_pages);
	++plist->pl_nr;
	lu_ref_add_at(&page->cp_reference, &page->cp_queue_ref, "queue", plist);
	cl_page_get(page);
	EXIT;
}
EXPORT_SYMBOL(cl_page_list_add);

/**
 * Removes a page from a page list.
 */
void cl_page_list_del(const struct lu_env *env,
		      struct cl_page_list *plist, struct cl_page *page)
{
	LASSERT(plist->pl_nr > 0);
	LASSERT(cl_page_is_vmlocked(env, page));
	LINVRNT(plist->pl_owner == current);

	ENTRY;
	list_del_init(&page->cp_batch);
	--plist->pl_nr;
	lu_ref_del_at(&page->cp_reference, &page->cp_queue_ref, "queue", plist);
	cl_page_put(env, page);
	EXIT;
}
EXPORT_SYMBOL(cl_page_list_del);

/**
 * Moves a page from one page list to another.
 */
void cl_page_list_move(struct cl_page_list *dst, struct cl_page_list *src,
		       struct cl_page *page)
{
	LASSERT(src->pl_nr > 0);
	LINVRNT(dst->pl_owner == current);
	LINVRNT(src->pl_owner == current);

	ENTRY;
	list_move_tail(&page->cp_batch, &dst->pl_pages);
	--src->pl_nr;
	++dst->pl_nr;
	lu_ref_set_at(&page->cp_reference, &page->cp_queue_ref, "queue",
		      src, dst);
	EXIT;
}
EXPORT_SYMBOL(cl_page_list_move);

/**
 * Moves a page from one page list to the head of another list.
 */
void cl_page_list_move_head(struct cl_page_list *dst, struct cl_page_list *src,
			    struct cl_page *page)
{
	LASSERT(src->pl_nr > 0);
	LINVRNT(dst->pl_owner == current);
	LINVRNT(src->pl_owner == current);

	ENTRY;
	list_move(&page->cp_batch, &dst->pl_pages);
	--src->pl_nr;
	++dst->pl_nr;
	lu_ref_set_at(&page->cp_reference, &page->cp_queue_ref, "queue",
			src, dst);
	EXIT;
}
EXPORT_SYMBOL(cl_page_list_move_head);

/**
 * splice the cl_page_list, just as list head does
 */
void cl_page_list_splice(struct cl_page_list *list, struct cl_page_list *head)
{
	struct cl_page *page;
	struct cl_page *tmp;

	LINVRNT(list->pl_owner == current);
	LINVRNT(head->pl_owner == current);

	ENTRY;
	cl_page_list_for_each_safe(page, tmp, list)
		cl_page_list_move(head, list, page);
	EXIT;
}
EXPORT_SYMBOL(cl_page_list_splice);

/**
 * Disowns pages in a queue.
 */
void cl_page_list_disown(const struct lu_env *env,
			 struct cl_io *io, struct cl_page_list *plist)
{
	struct cl_page *page;
	struct cl_page *temp;

	LINVRNT(plist->pl_owner == current);

	ENTRY;
	cl_page_list_for_each_safe(page, temp, plist) {
		LASSERT(plist->pl_nr > 0);

		list_del_init(&page->cp_batch);
		--plist->pl_nr;
		/*
		 * cl_page_disown0 rather than usual cl_page_disown() is used,
		 * because pages are possibly in CPS_FREEING state already due
		 * to the call to cl_page_list_discard().
		 */
		/*
		 * XXX cl_page_disown0() will fail if page is not locked.
		 */
		cl_page_disown0(env, io, page);
		lu_ref_del_at(&page->cp_reference, &page->cp_queue_ref, "queue",
			      plist);
		cl_page_put(env, page);
	}
	EXIT;
}
EXPORT_SYMBOL(cl_page_list_disown);

/**
 * Releases pages from queue.
 */
void cl_page_list_fini(const struct lu_env *env, struct cl_page_list *plist)
{
	struct cl_page *page;
	struct cl_page *temp;

	LINVRNT(plist->pl_owner == current);

	ENTRY;
	cl_page_list_for_each_safe(page, temp, plist)
		cl_page_list_del(env, plist, page);
	LASSERT(plist->pl_nr == 0);
	EXIT;
}
EXPORT_SYMBOL(cl_page_list_fini);

/**
 * Assumes all pages in a queue.
 */
void cl_page_list_assume(const struct lu_env *env,
			 struct cl_io *io, struct cl_page_list *plist)
{
	struct cl_page *page;

	LINVRNT(plist->pl_owner == current);

	cl_page_list_for_each(page, plist)
		cl_page_assume(env, io, page);
}

/**
 * Discards all pages in a queue.
 */
void cl_page_list_discard(const struct lu_env *env, struct cl_io *io,
			  struct cl_page_list *plist)
{
	struct cl_page *page;

	LINVRNT(plist->pl_owner == current);
	ENTRY;
	cl_page_list_for_each(page, plist)
		cl_page_discard(env, io, page);
	EXIT;
}

/**
 * Initialize dual page queue.
 */
void cl_2queue_init(struct cl_2queue *queue)
{
        ENTRY;
        cl_page_list_init(&queue->c2_qin);
        cl_page_list_init(&queue->c2_qout);
        EXIT;
}
EXPORT_SYMBOL(cl_2queue_init);

/**
 * Add a page to the incoming page list of 2-queue.
 */
void cl_2queue_add(struct cl_2queue *queue, struct cl_page *page)
{
        ENTRY;
        cl_page_list_add(&queue->c2_qin, page);
        EXIT;
}
EXPORT_SYMBOL(cl_2queue_add);

/**
 * Disown pages in both lists of a 2-queue.
 */
void cl_2queue_disown(const struct lu_env *env,
                      struct cl_io *io, struct cl_2queue *queue)
{
        ENTRY;
        cl_page_list_disown(env, io, &queue->c2_qin);
        cl_page_list_disown(env, io, &queue->c2_qout);
        EXIT;
}
EXPORT_SYMBOL(cl_2queue_disown);

/**
 * Discard (truncate) pages in both lists of a 2-queue.
 */
void cl_2queue_discard(const struct lu_env *env,
                       struct cl_io *io, struct cl_2queue *queue)
{
        ENTRY;
        cl_page_list_discard(env, io, &queue->c2_qin);
        cl_page_list_discard(env, io, &queue->c2_qout);
        EXIT;
}
EXPORT_SYMBOL(cl_2queue_discard);

/**
 * Assume to own the pages in cl_2queue
 */
void cl_2queue_assume(const struct lu_env *env,
                      struct cl_io *io, struct cl_2queue *queue)
{
        cl_page_list_assume(env, io, &queue->c2_qin);
        cl_page_list_assume(env, io, &queue->c2_qout);
}

/**
 * Finalize both page lists of a 2-queue.
 */
void cl_2queue_fini(const struct lu_env *env, struct cl_2queue *queue)
{
        ENTRY;
        cl_page_list_fini(env, &queue->c2_qout);
        cl_page_list_fini(env, &queue->c2_qin);
        EXIT;
}
EXPORT_SYMBOL(cl_2queue_fini);

/**
 * Initialize a 2-queue to contain \a page in its incoming page list.
 */
void cl_2queue_init_page(struct cl_2queue *queue, struct cl_page *page)
{
        ENTRY;
        cl_2queue_init(queue);
        cl_2queue_add(queue, page);
        EXIT;
}
EXPORT_SYMBOL(cl_2queue_init_page);

/**
 * Returns top-level io.
 *
 * \see cl_object_top()
 */
struct cl_io *cl_io_top(struct cl_io *io)
{
        ENTRY;
        while (io->ci_parent != NULL)
                io = io->ci_parent;
        RETURN(io);
}
EXPORT_SYMBOL(cl_io_top);

/**
 * Prints human readable representation of \a io to the \a f.
 */
void cl_io_print(const struct lu_env *env, void *cookie,
                 lu_printer_t printer, const struct cl_io *io)
{
}

/**
 * Fills in attributes that are passed to server together with transfer. Only
 * attributes from \a flags may be touched. This can be called multiple times
 * for the same request.
 */
void cl_req_attr_set(const struct lu_env *env, struct cl_object *obj,
		     struct cl_req_attr *attr)
{
	struct cl_object *scan;
	ENTRY;

	cl_object_for_each(scan, obj) {
		if (scan->co_ops->coo_req_attr_set != NULL)
			scan->co_ops->coo_req_attr_set(env, scan, attr);
	}
	EXIT;
}
EXPORT_SYMBOL(cl_req_attr_set);

/* cl_sync_io_callback assumes the caller must call cl_sync_io_wait() to
 * wait for the IO to finish. */
void cl_sync_io_end(const struct lu_env *env, struct cl_sync_io *anchor)
{
	wake_up_all(&anchor->csi_waitq);

	/* it's safe to nuke or reuse anchor now */
	atomic_set(&anchor->csi_barrier, 0);
}
EXPORT_SYMBOL(cl_sync_io_end);

/**
 * Initialize synchronous io wait anchor
 */
void cl_sync_io_init(struct cl_sync_io *anchor, int nr,
		     void (*end)(const struct lu_env *, struct cl_sync_io *))
{
	ENTRY;
	memset(anchor, 0, sizeof(*anchor));
	init_waitqueue_head(&anchor->csi_waitq);
	atomic_set(&anchor->csi_sync_nr, nr);
	atomic_set(&anchor->csi_barrier, nr > 0);
	anchor->csi_sync_rc = 0;
	anchor->csi_end_io = end;
	LASSERT(end != NULL);
	EXIT;
}
EXPORT_SYMBOL(cl_sync_io_init);

/**
 * Wait until all IO completes. Transfer completion routine has to call
 * cl_sync_io_note() for every entity.
 */
int cl_sync_io_wait(const struct lu_env *env, struct cl_sync_io *anchor,
		    long timeout)
{
	struct l_wait_info lwi = LWI_TIMEOUT_INTR(cfs_time_seconds(timeout),
						  NULL, NULL, NULL);
	int rc;
	ENTRY;

	LASSERT(timeout >= 0);

	rc = l_wait_event(anchor->csi_waitq,
			  atomic_read(&anchor->csi_sync_nr) == 0,
			  &lwi);
	if (rc < 0) {
		CERROR("IO failed: %d, still wait for %d remaining entries\n",
		       rc, atomic_read(&anchor->csi_sync_nr));

		lwi = (struct l_wait_info) { 0 };
		(void)l_wait_event(anchor->csi_waitq,
				   atomic_read(&anchor->csi_sync_nr) == 0,
				   &lwi);
	} else {
		rc = anchor->csi_sync_rc;
	}
	LASSERT(atomic_read(&anchor->csi_sync_nr) == 0);

	/* wait until cl_sync_io_note() has done wakeup */
	while (unlikely(atomic_read(&anchor->csi_barrier) != 0)) {
		cpu_relax();
	}
	RETURN(rc);
}
EXPORT_SYMBOL(cl_sync_io_wait);

/**
 * Indicate that transfer of a single page completed.
 */
void cl_sync_io_note(const struct lu_env *env, struct cl_sync_io *anchor,
		     int ioret)
{
	ENTRY;
	if (anchor->csi_sync_rc == 0 && ioret < 0)
		anchor->csi_sync_rc = ioret;
	/*
	 * Synchronous IO done without releasing page lock (e.g., as a part of
	 * ->{prepare,commit}_write(). Completion is used to signal the end of
	 * IO.
	 */
	LASSERT(atomic_read(&anchor->csi_sync_nr) > 0);
	if (atomic_dec_and_test(&anchor->csi_sync_nr)) {
		LASSERT(anchor->csi_end_io != NULL);
		anchor->csi_end_io(env, anchor);
		/* Can't access anchor any more */
	}
	EXIT;
}
EXPORT_SYMBOL(cl_sync_io_note);
