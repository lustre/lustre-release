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
 * Lustre is a trademark of Sun Microsystems, Inc.
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

        /* mmap_sem must have been held by caller. */
        LASSERT(!down_write_trylock(&mm->mmap_sem));

        for(vma = find_vma(mm, addr);
            vma != NULL && vma->vm_start < (addr + count); vma = vma->vm_next) {
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
 * \parm ra_flags - vma readahead flags.
 *
 * \return error codes from cl_io_init.
 */
static struct cl_io *
ll_fault_io_init(struct lu_env *env, struct vm_area_struct *vma,
		 pgoff_t index, unsigned long *ra_flags)
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
        fio->ft_index      = index;
        fio->ft_executable = vma->vm_flags&VM_EXEC;

        /*
         * disable VM_SEQ_READ and use VM_RAND_READ to make sure that
         * the kernel will not read other pages not covered by ldlm in
         * filemap_nopage. we do our readahead in ll_readpage.
         */
        if (ra_flags != NULL)
                *ra_flags = vma->vm_flags & (VM_RAND_READ|VM_SEQ_READ);
        vma->vm_flags &= ~VM_SEQ_READ;
        vma->vm_flags |= VM_RAND_READ;

        CDEBUG(D_MMAP, "vm_flags: %lx (%lu %d)\n", vma->vm_flags,
               fio->ft_index, fio->ft_executable);

	rc = cl_io_init(env, io, CIT_FAULT, io->ci_obj);
	if (rc == 0) {
		struct vvp_io *vio = vvp_env_io(env);
		struct ll_file_data *fd = LUSTRE_FPRIVATE(file);

		LASSERT(vio->vui_cl.cis_io == io);

		/* mmap lock must be MANDATORY it has to cache
		 * pages. */
		io->ci_lockreq = CILR_MANDATORY;
		vio->vui_fd = fd;
	} else {
		LASSERT(rc < 0);
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
	sigset_t		 set;
	struct inode             *inode;
	struct ll_inode_info     *lli;
	ENTRY;

	LASSERT(vmpage != NULL);
	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io = ll_fault_io_init(env, vma, vmpage->index, NULL);
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

	set = cfs_block_sigsinv(sigmask(SIGKILL) | sigmask(SIGTERM));

	inode = vvp_object_inode(io->ci_obj);
	lli = ll_i2info(inode);

	result = cl_io_loop(env, io);

	cfs_restore_sigs(set);

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
			ll_file_set_flag(lli, LLIF_DATA_MODIFIED);
        }
        EXIT;

out_io:
	cl_io_fini(env, io);
out:
	cl_env_put(env, &refcheck);
	CDEBUG(D_MMAP, "%s mkwrite with %d\n", current->comm, result);
	LASSERT(ergo(result == 0, PageLocked(vmpage)));

	return result;
}

static inline int to_fault_error(int result)
{
	switch(result) {
	case 0:
		result = VM_FAULT_LOCKED;
		break;
	case -EFAULT:
		result = VM_FAULT_NOPAGE;
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
static int ll_fault0(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct lu_env           *env;
	struct cl_io            *io;
	struct vvp_io           *vio = NULL;
	struct page             *vmpage;
	unsigned long            ra_flags;
	int                      result = 0;
	int                      fault_ret = 0;
	__u16			 refcheck;
	ENTRY;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	if (ll_sbi_has_fast_read(ll_i2sbi(file_inode(vma->vm_file)))) {
		/* do fast fault */
		ll_cl_add(vma->vm_file, env, NULL, LCC_MMAP);
		fault_ret = ll_filemap_fault(vma, vmf);
		ll_cl_remove(vma->vm_file, env);

		/* - If there is no error, then the page was found in cache and
		 *   uptodate;
		 * - If VM_FAULT_RETRY is set, the page existed but failed to
		 *   lock. It will return to kernel and retry;
		 * - Otherwise, it should try normal fault under DLM lock. */
		if ((fault_ret & VM_FAULT_RETRY) ||
		    !(fault_ret & VM_FAULT_ERROR))
			GOTO(out, result = 0);

		fault_ret = 0;
	}

	io = ll_fault_io_init(env, vma, vmf->pgoff, &ra_flags);
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

	vma->vm_flags |= ra_flags;

out:
	cl_env_put(env, &refcheck);
	if (result != 0 && !(fault_ret & VM_FAULT_RETRY))
		fault_ret |= to_fault_error(result);

	CDEBUG(D_MMAP, "%s fault %d/%d\n", current->comm, fault_ret, result);
	RETURN(fault_ret);
}

#ifdef HAVE_VM_OPS_USE_VM_FAULT_ONLY
static int ll_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#else
static int ll_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
#endif
	int count = 0;
	bool printed = false;
	int result;
	sigset_t set;

	/* Only SIGKILL and SIGTERM is allowed for fault/nopage/mkwrite
	 * so that it can be killed by admin but not cause segfault by
	 * other signals. */
	set = cfs_block_sigsinv(sigmask(SIGKILL) | sigmask(SIGTERM));

	ll_stats_ops_tally(ll_i2sbi(file_inode(vma->vm_file)),
			   LPROC_LL_FAULT, 1);

restart:
	result = ll_fault0(vma, vmf);
	if (!(result & (VM_FAULT_RETRY | VM_FAULT_ERROR | VM_FAULT_LOCKED))) {
                struct page *vmpage = vmf->page;

                /* check if this page has been truncated */
                lock_page(vmpage);
                if (unlikely(vmpage->mapping == NULL)) { /* unlucky */
                        unlock_page(vmpage);
			put_page(vmpage);
                        vmf->page = NULL;

                        if (!printed && ++count > 16) {
                                CWARN("the page is under heavy contention,"
                                      "maybe your app(%s) needs revising :-)\n",
                                      current->comm);
                                printed = true;
                        }

                        goto restart;
                }

                result |= VM_FAULT_LOCKED;
        }
	cfs_restore_sigs(set);
        return result;
}

#ifdef HAVE_VM_OPS_USE_VM_FAULT_ONLY
static int ll_page_mkwrite(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#else
static int ll_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
#endif
	int count = 0;
	bool printed = false;
	bool retry;
	int result;

	ll_stats_ops_tally(ll_i2sbi(file_inode(vma->vm_file)),
			   LPROC_LL_MKWRITE, 1);

	file_update_time(vma->vm_file);
        do {
                retry = false;
                result = ll_page_mkwrite0(vma, vmf->page, &retry);

                if (!printed && ++count > 16) {
			const struct dentry *de = file_dentry(vma->vm_file);

			CWARN("app(%s): the page %lu of file "DFID" is under"
			      " heavy contention\n",
			      current->comm, vmf->pgoff,
			      PFID(ll_inode2fid(de->d_inode)));
                        printed = true;
                }
        } while (retry);

        switch(result) {
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
	EXIT;
}

/* XXX put nice comment here.  talk about __free_pte -> dirty pages and
 * nopage's reference passing to the pte */
int ll_teardown_mmaps(struct address_space *mapping, __u64 first, __u64 last)
{
        int rc = -ENOENT;
        ENTRY;

	LASSERTF(last > first, "last %llu first %llu\n", last, first);
        if (mapping_mapped(mapping)) {
                rc = 0;
		unmap_mapping_range(mapping, first + PAGE_SIZE - 1,
                                    last - first + 1, 0);
        }

        RETURN(rc);
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
        int rc;
        ENTRY;

        if (ll_file_nolock(file))
                RETURN(-EOPNOTSUPP);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_MAP, 1);
        rc = generic_file_mmap(file, vma);
        if (rc == 0) {
                vma->vm_ops = &ll_file_vm_ops;
                vma->vm_ops->open(vma);
                /* update the inode's size and mtime */
                rc = ll_glimpse_size(inode);
        }

        RETURN(rc);
}
