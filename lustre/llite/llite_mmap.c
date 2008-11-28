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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
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

#define DEBUG_SUBSYSTEM S_LLITE

//#include <lustre_mdc.h>
#include <lustre_lite.h>
#include "llite_internal.h"
#include <linux/lustre_compat25.h>

#define VMA_DEBUG(vma, fmt, arg...)                                     \
        CDEBUG(D_MMAP, "vma(%p) start(%ld) end(%ld) pgoff(%ld) inode(%p) "   \
               "ino(%lu) iname(%s): " fmt, vma, vma->vm_start, vma->vm_end,  \
               vma->vm_pgoff, vma->vm_file->f_dentry->d_inode,               \
               vma->vm_file->f_dentry->d_inode->i_ino,                       \
               vma->vm_file->f_dentry->d_iname, ## arg);                     \

struct page *ll_nopage(struct vm_area_struct *vma, unsigned long address,
                       int *type);

void policy_from_vma(ldlm_policy_data_t *policy,
                            struct vm_area_struct *vma, unsigned long addr,
                            size_t count)
{
        policy->l_extent.start = ((addr - vma->vm_start) & CFS_PAGE_MASK) +
                                 (vma->vm_pgoff << CFS_PAGE_SHIFT);
        policy->l_extent.end = (policy->l_extent.start + count - 1) |
                               ~CFS_PAGE_MASK;
}

struct vm_area_struct * our_vma(unsigned long addr, size_t count)
{
        struct mm_struct *mm = current->mm;
        struct vm_area_struct *vma, *ret = NULL;
        ENTRY;

        /* No MM (e.g. NFS)? No vmas too. */
        if (!mm)
                RETURN(NULL);

        spin_lock(&mm->page_table_lock);
        for(vma = find_vma(mm, addr);
            vma != NULL && vma->vm_start < (addr + count); vma = vma->vm_next) {
                if (vma->vm_ops && vma->vm_ops->nopage == ll_nopage &&
                    vma->vm_flags & VM_SHARED) {
                        ret = vma;
                        break;
                }
        }
        spin_unlock(&mm->page_table_lock);
        RETURN(ret);
}

/**
 * Lustre implementation of a vm_operations_struct::nopage() method, called by
 * VM to server page fault (both in kernel and user space).
 *
 * This function sets up CIT_FAULT cl_io that does the job.
 *
 * \param vma - is virtiual area struct related to page fault
 * \param address - address when hit fault
 * \param type - of fault
 *
 * XXX newer 2.6 kernels provide vm_operations_struct::fault() method with
 * slightly different semantics instead.
 *
 * \return allocated and filled page for address
 * \retval NOPAGE_SIGBUS if page not exist on this address
 * \retval NOPAGE_OOM not have memory for allocate new page
 */
struct page *ll_nopage(struct vm_area_struct *vma, unsigned long address,
                       int *type)
{
        struct file       *file  = vma->vm_file;
        struct inode      *inode = file->f_dentry->d_inode;
        struct lu_env     *env;
        struct cl_io      *io;
        struct page       *page  = NULL;
        struct cl_env_nest nest;
        int result;

        ENTRY;

        /*
         * vm_operations_struct::nopage() can be called when lustre IO is
         * already active for the current thread, e.g., when doing read/write
         * against user level buffer mapped from Lustre buffer. To avoid
         * stomping on existing context, optionally force an allocation of a new
         * one.
         */
        env = cl_env_nested_get(&nest);
        if (!IS_ERR(env)) {
                pgoff_t pg_offset;
                const unsigned long writable = VM_SHARED|VM_WRITE;
                unsigned long ra_flags;
                struct cl_fault_io *fio;

                io = &ccc_env_info(env)->cti_io;
                io->ci_obj = ll_i2info(inode)->lli_clob;
                LASSERT(io->ci_obj != NULL);

                fio = &io->u.ci_fault;
                pg_offset = (address - vma->vm_start) >> PAGE_SHIFT;
                fio->ft_index      = pg_offset + vma->vm_pgoff;
                fio->ft_writable   = (vma->vm_flags&writable) == writable;
                fio->ft_executable = vma->vm_flags&VM_EXEC;

                /*
                 * disable VM_SEQ_READ and use VM_RAND_READ to make sure that
                 * the kernel will not read other pages not covered by ldlm in
                 * filemap_nopage. we do our readahead in ll_readpage.
                 */
                ra_flags = vma->vm_flags & (VM_RAND_READ|VM_SEQ_READ);
                vma->vm_flags &= ~VM_SEQ_READ;
                vma->vm_flags |= VM_RAND_READ;

                CDEBUG(D_INFO, "vm_flags: %lx (%lu %i %i)\n", vma->vm_flags,
                       fio->ft_index, fio->ft_writable, fio->ft_executable);

                if (cl_io_init(env, io, CIT_FAULT, io->ci_obj) == 0) {
                        struct vvp_io *vio = vvp_env_io(env);
                        struct ccc_io *cio = ccc_env_io(env);

                        LASSERT(cio->cui_cl.cis_io == io);

                        vio->u.fault.ft_vma     = vma;
                        vio->u.fault.ft_address = address;
                        vio->u.fault.ft_type    = type;
                        cio->cui_fd = LUSTRE_FPRIVATE(file);

                        result = cl_io_loop(env, io);
                        if (result == 0) {
                                LASSERT(fio->ft_page != NULL);
                                page = cl_page_vmpage(env, fio->ft_page);
                        } else if (result == -EFAULT) {
                                page = NOPAGE_SIGBUS;
                        } else if (result == -ENOMEM) {
                                page = NOPAGE_OOM;
                        }
                } else
                        result = io->ci_result;

                vma->vm_flags &= ~VM_RAND_READ;
                vma->vm_flags |= ra_flags;

                cl_io_fini(env, io);
                cl_env_nested_put(&nest, env);
        }
        RETURN(page);
}

/**
 *  To avoid cancel the locks covering mmapped region for lock cache pressure,
 *  we track the mapped vma count in ccc_object::cob_mmap_cnt.
 */
static void ll_vm_open(struct vm_area_struct * vma)
{
        struct inode *inode    = vma->vm_file->f_dentry->d_inode;
        struct ccc_object *vob = cl_inode2ccc(inode);

        ENTRY;
        LASSERT(vma->vm_file);
        LASSERT(atomic_read(&vob->cob_mmap_cnt) >= 0);
        atomic_inc(&vob->cob_mmap_cnt);
        EXIT;
}

/**
 * Dual to ll_vm_open().
 */
static void ll_vm_close(struct vm_area_struct *vma)
{
        struct inode      *inode = vma->vm_file->f_dentry->d_inode;
        struct ccc_object *vob   = cl_inode2ccc(inode);

        ENTRY;
        LASSERT(vma->vm_file);
        atomic_dec(&vob->cob_mmap_cnt);
        LASSERT(atomic_read(&vob->cob_mmap_cnt) >= 0);
        EXIT;
}

#ifndef HAVE_FILEMAP_POPULATE
static int (*filemap_populate)(struct vm_area_struct * area, unsigned long address, unsigned long len, pgprot_t prot, unsigned long pgoff, int nonblock);
#endif
static int ll_populate(struct vm_area_struct *area, unsigned long address,
                       unsigned long len, pgprot_t prot, unsigned long pgoff,
                       int nonblock)
{
        int rc = 0;
        ENTRY;

        /* always set nonblock as true to avoid page read ahead */
        rc = filemap_populate(area, address, len, prot, pgoff, 1);
        RETURN(rc);
}

/* return the user space pointer that maps to a file offset via a vma */
static inline unsigned long file_to_user(struct vm_area_struct *vma, __u64 byte)
{
        return vma->vm_start + (byte - ((__u64)vma->vm_pgoff << CFS_PAGE_SHIFT));

}

/* XXX put nice comment here.  talk about __free_pte -> dirty pages and
 * nopage's reference passing to the pte */
int ll_teardown_mmaps(struct address_space *mapping, __u64 first, __u64 last)
{
        int rc = -ENOENT;
        ENTRY;

        LASSERTF(last > first, "last "LPU64" first "LPU64"\n", last, first);
        if (mapping_mapped(mapping)) {
                rc = 0;
                unmap_mapping_range(mapping, first + CFS_PAGE_SIZE - 1,
                                    last - first + 1, 0);
        }

        RETURN(rc);
}

static struct vm_operations_struct ll_file_vm_ops = {
        .nopage         = ll_nopage,
        .open           = ll_vm_open,
        .close          = ll_vm_close,
        .populate       = ll_populate,
};

int ll_file_mmap(struct file * file, struct vm_area_struct * vma)
{
        int rc;
        ENTRY;

        ll_stats_ops_tally(ll_i2sbi(file->f_dentry->d_inode), LPROC_LL_MAP, 1);
        rc = generic_file_mmap(file, vma);
        if (rc == 0) {
#if !defined(HAVE_FILEMAP_POPULATE)
                if (!filemap_populate)
                        filemap_populate = vma->vm_ops->populate;
#endif
                vma->vm_ops = &ll_file_vm_ops;
                vma->vm_ops->open(vma);
                /* update the inode's size and mtime */
                rc = cl_glimpse_size(file->f_dentry->d_inode);
        }

        RETURN(rc);
}
