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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include "llite_internal.h"
#include <lustre_compat.h>

static const struct vm_operations_struct ll_file_vm_ops;

void policy_from_vma(union ldlm_policy_data *policy, struct vm_area_struct *vma,
		     unsigned long addr, size_t count)
{
	policy->l_extent.start = ((addr - vma->vm_start) & PAGE_MASK) +
				 (vma->vm_pgoff << PAGE_SHIFT);
	policy->l_extent.end = (policy->l_extent.start + count - 1) |
			       ~PAGE_MASK;
}

struct vm_area_struct *our_vma(struct mm_struct *mm, unsigned long addr,
                               size_t count)
{
	struct vm_area_struct *vma, *ret = NULL;
	ENTRY;

	/* mmap_lock must have been held by caller. */
	LASSERT(!mmap_write_trylock(mm));

	for (vma = find_vma(mm, addr);
	     vma != NULL && vma->vm_start < (addr + count);
	     vma = vma->vm_next) {
		if (vma->vm_ops && vma->vm_ops == &ll_file_vm_ops &&
		    vma->vm_flags & VM_SHARED) {
			ret = vma;
			break;
		}
	}
	RETURN(ret);
}

/**
 * API independent part for page fault initialization.
 * \param env - corespondent lu_env to processing
 * \param vma - virtual memory area addressed to page fault
 * \param index - page index corespondent to fault.
 *
 * \return error codes from cl_io_init.
 */
static struct cl_io *
ll_fault_io_init(struct lu_env *env, struct vm_area_struct *vma, pgoff_t index)
{
	struct file	       *file = vma->vm_file;
	struct inode	       *inode = file_inode(file);
	struct cl_io	       *io;
	struct cl_fault_io     *fio;
	int			rc;
	ENTRY;

	if (ll_file_nolock(file))
		RETURN(ERR_PTR(-EOPNOTSUPP));

restart:
	io = vvp_env_thread_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;
	LASSERT(io->ci_obj != NULL);

	fio = &io->u.ci_fault;
	fio->ft_index = index;
	fio->ft_executable = vma->vm_flags & VM_EXEC;

	CDEBUG(D_MMAP,
	       DFID": vma=%p start=%#lx end=%#lx vm_flags=%#lx idx=%lu\n",
	       PFID(&ll_i2info(inode)->lli_fid), vma, vma->vm_start,
	       vma->vm_end, vma->vm_flags, fio->ft_index);

	if (vma->vm_flags & VM_SEQ_READ)
		io->ci_seq_read = 1;
	else if (vma->vm_flags & VM_RAND_READ)
		io->ci_rand_read = 1;

	if (vma->vm_flags & VM_WRITE)
		fio->ft_writable = 1;

	rc = cl_io_init(env, io, CIT_FAULT, io->ci_obj);
	if (rc == 0) {
		struct vvp_io *vio = vvp_env_io(env);
		struct ll_file_data *fd = file->private_data;

		LASSERT(vio->vui_cl.cis_io == io);

		/* mmap lock must be MANDATORY it has to cache
		 * pages. */
		io->ci_lockreq = CILR_MANDATORY;
		vio->vui_fd = fd;
	} else {
		cl_io_fini(env, io);
		if (io->ci_need_restart)
			goto restart;

		io = ERR_PTR(rc);
	}

	RETURN(io);
}

/* Sharing code of page_mkwrite method for rhel5 and rhel6 */
static int ll_page_mkwrite0(struct vm_area_struct *vma, struct page *vmpage,
                            bool *retry)
{
	struct lu_env           *env;
	struct cl_io            *io;
	struct vvp_io           *vio;
	int                      result;
	__u16			 refcheck;
	sigset_t old, new;
	struct inode             *inode = NULL;
	struct ll_inode_info     *lli;
	ENTRY;

	LASSERT(vmpage != NULL);
	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io = ll_fault_io_init(env, vma, vmpage->index);
	if (IS_ERR(io))
		GOTO(out, result = PTR_ERR(io));

	result = io->ci_result;
	if (result < 0)
		GOTO(out_io, result);

	io->u.ci_fault.ft_mkwrite = 1;
	io->u.ci_fault.ft_writable = 1;

	vio = vvp_env_io(env);
	vio->u.fault.ft_vma    = vma;
	vio->u.fault.ft_vmpage = vmpage;

	siginitsetinv(&new, sigmask(SIGKILL) | sigmask(SIGTERM));
	sigprocmask(SIG_BLOCK, &new, &old);

	inode = vvp_object_inode(io->ci_obj);
	lli = ll_i2info(inode);

	result = cl_io_loop(env, io);

	sigprocmask(SIG_SETMASK, &old, NULL);

        if (result == 0) {
                lock_page(vmpage);
                if (vmpage->mapping == NULL) {
                        unlock_page(vmpage);

                        /* page was truncated and lock was cancelled, return
                         * ENODATA so that VM_FAULT_NOPAGE will be returned
                         * to handle_mm_fault(). */
                        if (result == 0)
                                result = -ENODATA;
                } else if (!PageDirty(vmpage)) {
                        /* race, the page has been cleaned by ptlrpcd after
                         * it was unlocked, it has to be added into dirty
                         * cache again otherwise this soon-to-dirty page won't
                         * consume any grants, even worse if this page is being
                         * transferred because it will break RPC checksum.
                         */
                        unlock_page(vmpage);

                        CDEBUG(D_MMAP, "Race on page_mkwrite %p/%lu, page has "
                               "been written out, retry.\n",
                               vmpage, vmpage->index);

                        *retry = true;
                        result = -EAGAIN;
                }

		if (result == 0)
			set_bit(LLIF_DATA_MODIFIED, &lli->lli_flags);
        }
        EXIT;

out_io:
	cl_io_fini(env, io);
out:
	cl_env_put(env, &refcheck);
	CDEBUG(D_MMAP, "%s mkwrite with %d\n", current->comm, result);
	LASSERT(ergo(result == 0, PageLocked(vmpage)));

	/* if page has been unmapped, presumably due to lock reclaim for
	 * concurrent usage, add some delay before retrying to prevent
	 * entering live-lock situation with competitors
	 */
	if (result == -ENODATA && inode != NULL) {
		CDEBUG(D_MMAP, "delaying new page-fault for inode %p to "
			       "prevent live-lock\n", inode);
		msleep(10);
	}

	return result;
}

static inline int to_fault_error(int result)
{
	switch(result) {
	case 0:
		result = VM_FAULT_LOCKED;
		break;
	case -ENOMEM:
		result = VM_FAULT_OOM;
		break;
	default:
		result = VM_FAULT_SIGBUS;
		break;
	}
	return result;
}

/**
 * Lustre implementation of a vm_operations_struct::fault() method, called by
 * VM to server page fault (both in kernel and user space).
 *
 * \param vma - is virtiual area struct related to page fault
 * \param vmf - structure which describe type and address where hit fault
 *
 * \return allocated and filled _locked_ page for address
 * \retval VM_FAULT_ERROR on general error
 * \retval NOPAGE_OOM not have memory for allocate new page
 */
static vm_fault_t ll_fault0(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct lu_env           *env;
	struct cl_io            *io;
	struct vvp_io           *vio = NULL;
	struct page             *vmpage;
	int                      result = 0;
	int                      fault_ret = 0;
	__u16			 refcheck;
	ENTRY;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	if (ll_sbi_has_fast_read(ll_i2sbi(file_inode(vma->vm_file)))) {
		/* do fast fault */
		bool has_retry = vmf->flags & FAULT_FLAG_RETRY_NOWAIT;

		/* To avoid loops, instruct downstream to not drop mmap_sem */
		vmf->flags |= FAULT_FLAG_RETRY_NOWAIT;
		ll_cl_add(vma->vm_file, env, NULL, LCC_MMAP);
		fault_ret = ll_filemap_fault(vma, vmf);
		ll_cl_remove(vma->vm_file, env);
		if (!has_retry)
			vmf->flags &= ~FAULT_FLAG_RETRY_NOWAIT;

		/* - If there is no error, then the page was found in cache and
		 *   uptodate;
		 * - If VM_FAULT_RETRY is set, the page existed but failed to
		 *   lock. We will try slow path to avoid loops.
		 * - Otherwise, it should try normal fault under DLM lock. */
		if (!(fault_ret & VM_FAULT_RETRY) &&
		    !(fault_ret & VM_FAULT_ERROR))
			GOTO(out, result = 0);

		fault_ret = 0;
	}

	io = ll_fault_io_init(env, vma, vmf->pgoff);
	if (IS_ERR(io))
		GOTO(out, result = PTR_ERR(io));

	result = io->ci_result;
	if (result == 0) {
		vio = vvp_env_io(env);
		vio->u.fault.ft_vma       = vma;
		vio->u.fault.ft_vmpage    = NULL;
		vio->u.fault.ft_vmf = vmf;
		vio->u.fault.ft_flags = 0;
		vio->u.fault.ft_flags_valid = 0;

		/* May call ll_readpage() */
		ll_cl_add(vma->vm_file, env, io, LCC_MMAP);

		result = cl_io_loop(env, io);

		ll_cl_remove(vma->vm_file, env);

		/* ft_flags are only valid if we reached
		 * the call to filemap_fault */
		if (vio->u.fault.ft_flags_valid)
			fault_ret = vio->u.fault.ft_flags;

		vmpage = vio->u.fault.ft_vmpage;
		if (result != 0 && vmpage != NULL) {
			put_page(vmpage);
			vmf->page = NULL;
		}
        }
	cl_io_fini(env, io);

out:
	cl_env_put(env, &refcheck);
	if (result != 0 && !(fault_ret & VM_FAULT_RETRY))
		fault_ret |= to_fault_error(result);

	CDEBUG(D_MMAP, "%s fault %d/%d\n", current->comm, fault_ret, result);
	RETURN(fault_ret);
}

#ifdef HAVE_VM_OPS_USE_VM_FAULT_ONLY
static vm_fault_t ll_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#else
static vm_fault_t ll_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
#endif
	int count = 0;
	bool printed = false;
	bool cached;
	vm_fault_t result;
	ktime_t kstart = ktime_get();
	sigset_t old, new;

	result = pcc_fault(vma, vmf, &cached);
	if (cached)
		goto out;

	CDEBUG(D_MMAP, DFID": vma=%p start=%#lx end=%#lx vm_flags=%#lx\n",
	       PFID(&ll_i2info(file_inode(vma->vm_file))->lli_fid),
	       vma, vma->vm_start, vma->vm_end, vma->vm_flags);

	/* Only SIGKILL and SIGTERM is allowed for fault/nopage/mkwrite
	 * so that it can be killed by admin but not cause segfault by
	 * other signals.
	 */
	siginitsetinv(&new, sigmask(SIGKILL) | sigmask(SIGTERM));
	sigprocmask(SIG_BLOCK, &new, &old);

	/* make sure offset is not a negative number */
	if (vmf->pgoff > (MAX_LFS_FILESIZE >> PAGE_SHIFT))
		return VM_FAULT_SIGBUS;

restart:
	result = ll_fault0(vma, vmf);
	if (vmf->page &&
	    !(result & (VM_FAULT_RETRY | VM_FAULT_ERROR | VM_FAULT_LOCKED))) {
		struct page *vmpage = vmf->page;

		/* check if this page has been truncated */
		lock_page(vmpage);
		if (unlikely(vmpage->mapping == NULL)) { /* unlucky */
			unlock_page(vmpage);
			put_page(vmpage);
			vmf->page = NULL;

			if (!printed && ++count > 16) {
				CWARN("the page is under heavy contention, maybe your app(%s) needs revising :-)\n",
				      current->comm);
				printed = true;
			}

			goto restart;
		}

		result |= VM_FAULT_LOCKED;
	}
	sigprocmask(SIG_SETMASK, &old, NULL);

out:
	if (vmf->page && result == VM_FAULT_LOCKED) {
		ll_rw_stats_tally(ll_i2sbi(file_inode(vma->vm_file)),
				  current->pid, vma->vm_file->private_data,
				  cl_offset(NULL, vmf->page->index), PAGE_SIZE,
				  READ);
		ll_stats_ops_tally(ll_i2sbi(file_inode(vma->vm_file)),
				   LPROC_LL_FAULT,
				   ktime_us_delta(ktime_get(), kstart));
	}

	return result;
}

#ifdef HAVE_VM_OPS_USE_VM_FAULT_ONLY
static vm_fault_t ll_page_mkwrite(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#else
static vm_fault_t ll_page_mkwrite(struct vm_area_struct *vma,
				  struct vm_fault *vmf)
{
#endif
	int count = 0;
	bool printed = false;
	bool retry;
	bool cached;
	ktime_t kstart = ktime_get();
	vm_fault_t result;

	result = pcc_page_mkwrite(vma, vmf, &cached);
	if (cached)
		goto out;

	file_update_time(vma->vm_file);
	do {
		retry = false;
		result = ll_page_mkwrite0(vma, vmf->page, &retry);

		if (!printed && ++count > 16) {
			const struct dentry *de = file_dentry(vma->vm_file);

			CWARN("app(%s): the page %lu of file "DFID" is under heavy contention\n",
			      current->comm, vmf->pgoff,
			      PFID(ll_inode2fid(de->d_inode)));
			printed = true;
		}
	} while (retry);

	switch (result) {
	case 0:
		LASSERT(PageLocked(vmf->page));
		result = VM_FAULT_LOCKED;
		break;
	case -ENODATA:
	case -EFAULT:
		result = VM_FAULT_NOPAGE;
		break;
	case -ENOMEM:
		result = VM_FAULT_OOM;
		break;
	case -EAGAIN:
		result = VM_FAULT_RETRY;
		break;
	default:
		result = VM_FAULT_SIGBUS;
		break;
	}

out:
	if (result == VM_FAULT_LOCKED) {
		ll_rw_stats_tally(ll_i2sbi(file_inode(vma->vm_file)),
				  current->pid, vma->vm_file->private_data,
				  cl_offset(NULL, vmf->page->index), PAGE_SIZE,
				  WRITE);
		ll_stats_ops_tally(ll_i2sbi(file_inode(vma->vm_file)),
				   LPROC_LL_MKWRITE,
				   ktime_us_delta(ktime_get(), kstart));
	}

	return result;
}

/**
 *  To avoid cancel the locks covering mmapped region for lock cache pressure,
 *  we track the mapped vma count in vvp_object::vob_mmap_cnt.
 */
static void ll_vm_open(struct vm_area_struct * vma)
{
	struct inode *inode    = file_inode(vma->vm_file);
	struct vvp_object *vob = cl_inode2vvp(inode);

	ENTRY;
	LASSERT(atomic_read(&vob->vob_mmap_cnt) >= 0);
	atomic_inc(&vob->vob_mmap_cnt);
	pcc_vm_open(vma);
	EXIT;
}

/**
 * Dual to ll_vm_open().
 */
static void ll_vm_close(struct vm_area_struct *vma)
{
	struct inode      *inode = file_inode(vma->vm_file);
	struct vvp_object *vob   = cl_inode2vvp(inode);

	ENTRY;
	atomic_dec(&vob->vob_mmap_cnt);
	LASSERT(atomic_read(&vob->vob_mmap_cnt) >= 0);
	pcc_vm_close(vma);
	EXIT;
}

static const struct vm_operations_struct ll_file_vm_ops = {
	.fault			= ll_fault,
	.page_mkwrite		= ll_page_mkwrite,
	.open			= ll_vm_open,
	.close			= ll_vm_close,
};

int ll_file_mmap(struct file *file, struct vm_area_struct * vma)
{
	struct inode *inode = file_inode(file);
	ktime_t kstart = ktime_get();
	bool cached;
	int rc;

	ENTRY;
	CDEBUG(D_VFSTRACE | D_MMAP,
	       "VFS_Op: fid="DFID" vma=%p start=%#lx end=%#lx vm_flags=%#lx\n",
	       PFID(&ll_i2info(inode)->lli_fid),
	       vma, vma->vm_start, vma->vm_end, vma->vm_flags);

	if (ll_file_nolock(file))
		RETURN(-EOPNOTSUPP);

	rc = pcc_file_mmap(file, vma, &cached);
	if (cached && rc != 0)
		RETURN(rc);

	rc = generic_file_mmap(file, vma);
	if (rc == 0) {
		vma->vm_ops = &ll_file_vm_ops;
		vma->vm_ops->open(vma);
		/* update the inode's size and mtime */
		if (!cached)
			rc = ll_glimpse_size(inode);
	}

	if (!rc)
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_MMAP,
				   ktime_us_delta(ktime_get(), kstart));

	RETURN(rc);
}
