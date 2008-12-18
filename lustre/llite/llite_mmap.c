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

#include <lustre_lite.h>
#include "llite_internal.h"
#include <linux/lustre_compat25.h>

#define VMA_DEBUG(vma, fmt, arg...)                                     \
        CDEBUG(D_MMAP, "vma(%p) start(%ld) end(%ld) pgoff(%ld) inode(%p) "   \
               "ino(%lu) iname(%s): " fmt, vma, vma->vm_start, vma->vm_end,  \
               vma->vm_pgoff, vma->vm_file->f_dentry->d_inode,               \
               vma->vm_file->f_dentry->d_inode->i_ino,                       \
               vma->vm_file->f_dentry->d_iname, ## arg);                     \


struct ll_lock_tree_node {
        rb_node_t               lt_node;
        struct list_head        lt_locked_item;
        __u64                   lt_oid;
        ldlm_policy_data_t      lt_policy;
        struct lustre_handle    lt_lockh;
        ldlm_mode_t             lt_mode;
        struct inode           *lt_inode;
};

int lt_get_mmap_locks(struct ll_lock_tree *tree,
                      unsigned long addr, size_t count);

struct page *ll_nopage(struct vm_area_struct *vma, unsigned long address,
                       int *type);

struct ll_lock_tree_node * ll_node_from_inode(struct inode *inode, __u64 start,
                                              __u64 end, ldlm_mode_t mode)
{
        struct ll_lock_tree_node *node;

        OBD_ALLOC(node, sizeof(*node));
        if (node == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        node->lt_inode = inode;
        node->lt_oid = ll_i2info(inode)->lli_smd->lsm_object_id;
        node->lt_policy.l_extent.start = start;
        node->lt_policy.l_extent.end = end;
        memset(&node->lt_lockh, 0, sizeof(node->lt_lockh));
        INIT_LIST_HEAD(&node->lt_locked_item);
        node->lt_mode = mode;

        return node;
}

int lt_compare(struct ll_lock_tree_node *one, struct ll_lock_tree_node *two)
{
        /* To avoid multiple fs deadlock */
        if (one->lt_inode->i_sb->s_dev < two->lt_inode->i_sb->s_dev)
                return -1;
        if (one->lt_inode->i_sb->s_dev > two->lt_inode->i_sb->s_dev)
                return 1;

        if (one->lt_oid < two->lt_oid)
                return -1;
        if (one->lt_oid > two->lt_oid)
                return 1;

        if (one->lt_policy.l_extent.end < two->lt_policy.l_extent.start)
                return -1;
        if (one->lt_policy.l_extent.start > two->lt_policy.l_extent.end)
                return 1;

        return 0; /* they are the same object and overlap */
}

static void lt_merge(struct ll_lock_tree_node *dst,
                     struct ll_lock_tree_node *src)
{
        dst->lt_policy.l_extent.start = min(dst->lt_policy.l_extent.start,
                                            src->lt_policy.l_extent.start);
        dst->lt_policy.l_extent.end = max(dst->lt_policy.l_extent.end,
                                          src->lt_policy.l_extent.end);

        /* XXX could be a real call to the dlm to find superset modes */
        if (src->lt_mode == LCK_PW && dst->lt_mode != LCK_PW)
                dst->lt_mode = LCK_PW;
}

static void lt_insert(struct ll_lock_tree *tree,
                      struct ll_lock_tree_node *node)
{
        struct ll_lock_tree_node *walk;
        rb_node_t **p, *parent;
        ENTRY;

restart:
        p = &tree->lt_root.rb_node;
        parent = NULL;
        while (*p) {
                parent = *p;
                walk = rb_entry(parent, struct ll_lock_tree_node, lt_node);
                switch (lt_compare(node, walk)) {
                case -1:
                        p = &(*p)->rb_left;
                        break;
                case 1:
                        p = &(*p)->rb_right;
                        break;
                case 0:
                        lt_merge(node, walk);
                        rb_erase(&walk->lt_node, &tree->lt_root);
                        OBD_FREE(walk, sizeof(*walk));
                        goto restart;
                        break;
                default:
                        LBUG();
                        break;
                }
        }
        rb_link_node(&node->lt_node, parent, p);
        rb_insert_color(&node->lt_node, &tree->lt_root);
        EXIT;
}

static struct ll_lock_tree_node *lt_least_node(struct ll_lock_tree *tree)
{
        rb_node_t *rbnode;
        struct ll_lock_tree_node *node = NULL;

        for ( rbnode = tree->lt_root.rb_node; rbnode != NULL;
              rbnode = rbnode->rb_left) {
                if (rbnode->rb_left == NULL) {
                        node = rb_entry(rbnode, struct ll_lock_tree_node,
                                        lt_node);
                        break;
                }
        }
        RETURN(node);
}

int ll_tree_unlock(struct ll_lock_tree *tree)
{
        struct ll_lock_tree_node *node;
        struct list_head *pos, *n;
        struct inode *inode;
        int rc = 0;
        ENTRY;

        list_for_each_safe(pos, n, &tree->lt_locked_list) {
                node = list_entry(pos, struct ll_lock_tree_node,
                                  lt_locked_item);

                inode = node->lt_inode;
                rc = ll_extent_unlock(tree->lt_fd, inode,
                                      ll_i2info(inode)->lli_smd, node->lt_mode,
                                      &node->lt_lockh);
                if (rc != 0) {
                        /* XXX better message */
                        CERROR("couldn't unlock %d\n", rc);
                }
                list_del(&node->lt_locked_item);
                OBD_FREE(node, sizeof(*node));
        }

        while ((node = lt_least_node(tree))) {
                rb_erase(&node->lt_node, &tree->lt_root);
                OBD_FREE(node, sizeof(*node));
        }

        RETURN(rc);
}

int ll_tree_lock_iov(struct ll_lock_tree *tree,
                 struct ll_lock_tree_node *first_node,
                 const struct iovec *iov, unsigned long nr_segs, int ast_flags)
{
        struct ll_lock_tree_node *node;
        int rc = 0;
        unsigned long seg;
        ENTRY;

        tree->lt_root.rb_node = NULL;
        INIT_LIST_HEAD(&tree->lt_locked_list);
        if (first_node != NULL)
                lt_insert(tree, first_node);

        /* To avoid such subtle deadlock case: client1 try to read file1 to
         * mmapped file2, on the same time, client2 try to read file2 to
         * mmapped file1.*/
        for (seg = 0; seg < nr_segs; seg++) {
                const struct iovec *iv = &iov[seg];
                rc = lt_get_mmap_locks(tree, (unsigned long)iv->iov_base,
                                       iv->iov_len);
                if (rc)
                        GOTO(out, rc);
        }

        while ((node = lt_least_node(tree))) {
                struct inode *inode = node->lt_inode;
                rc = ll_extent_lock(tree->lt_fd, inode,
                                    ll_i2info(inode)->lli_smd, node->lt_mode,
                                    &node->lt_policy, &node->lt_lockh,
                                    ast_flags);
                if (rc != 0)
                        GOTO(out, rc);

                rb_erase(&node->lt_node, &tree->lt_root);
                list_add_tail(&node->lt_locked_item, &tree->lt_locked_list);
        }
        RETURN(rc);
out:
        ll_tree_unlock(tree);
        RETURN(rc);
}

int ll_tree_lock(struct ll_lock_tree *tree,
                 struct ll_lock_tree_node *first_node,
                 const char *buf, size_t count, int ast_flags)
{
        struct iovec local_iov = { .iov_base = (void __user *)buf,
                                   .iov_len = count };

        return ll_tree_lock_iov(tree, first_node, &local_iov, 1, ast_flags);
}

static ldlm_mode_t mode_from_vma(struct vm_area_struct *vma)
{
        /* we only want to hold PW locks if the mmap() can generate
         * writes back to the file and that only happens in shared
         * writable vmas */
        if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_WRITE))
                return LCK_PW;
        return LCK_PR;
}

static void policy_from_vma(ldlm_policy_data_t *policy,
                            struct vm_area_struct *vma, unsigned long addr,
                            size_t count)
{
        policy->l_extent.start = ((addr - vma->vm_start) & CFS_PAGE_MASK) +
                                 ((__u64)vma->vm_pgoff << CFS_PAGE_SHIFT);
        policy->l_extent.end = (policy->l_extent.start + count - 1) |
                               ~CFS_PAGE_MASK;
}

static struct vm_area_struct * our_vma(unsigned long addr, size_t count)
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

int ll_region_mapped(unsigned long addr, size_t count)
{
        return !!our_vma(addr, count);
}

int lt_get_mmap_locks(struct ll_lock_tree *tree,
                      unsigned long addr, size_t count)
{
        struct vm_area_struct *vma;
        struct ll_lock_tree_node *node;
        ldlm_policy_data_t policy;
        struct inode *inode;
        ENTRY;

        if (count == 0)
                RETURN(0);

        /* we need to look up vmas on page aligned addresses */
        count += addr & (~CFS_PAGE_MASK);
        addr &= CFS_PAGE_MASK;

        while ((vma = our_vma(addr, count)) != NULL) {
                LASSERT(vma->vm_file);

                inode = vma->vm_file->f_dentry->d_inode;
                policy_from_vma(&policy, vma, addr, count);
                node = ll_node_from_inode(inode, policy.l_extent.start,
                                          policy.l_extent.end,
                                          mode_from_vma(vma));
                if (IS_ERR(node)) {
                        CERROR("not enough mem for lock_tree_node!\n");
                        RETURN(-ENOMEM);
                }
                lt_insert(tree, node);

                if (vma->vm_end - addr >= count)
                        break;
                count -= vma->vm_end - addr;
                addr = vma->vm_end;
        }
        RETURN(0);
}
/**
 * Page fault handler.
 *
 * \param vma - is virtiual area struct related to page fault
 * \param address - address when hit fault
 * \param type - of fault
 *
 * \return allocated and filled page for address
 * \retval NOPAGE_SIGBUS if page not exist on this address
 * \retval NOPAGE_OOM not have memory for allocate new page
 */
struct page *ll_nopage(struct vm_area_struct *vma, unsigned long address,
                       int *type)
{
        struct file *filp = vma->vm_file;
        struct ll_file_data *fd = LUSTRE_FPRIVATE(filp);
        struct inode *inode = filp->f_dentry->d_inode;
        struct lustre_handle lockh = { 0 };
        ldlm_policy_data_t policy;
        ldlm_mode_t mode;
        struct page *page = NULL;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm;
        struct ost_lvb lvb;
        __u64 kms, old_mtime;
        unsigned long pgoff, size, rand_read, seq_read;
        int rc = 0;
        ENTRY;

        if (lli->lli_smd == NULL) {
                CERROR("No lsm on fault?\n");
                RETURN(NOPAGE_SIGBUS);
        }

        ll_clear_file_contended(inode);

        /* start and end the lock on the first and last bytes in the page */
        policy_from_vma(&policy, vma, address, CFS_PAGE_SIZE);

        CDEBUG(D_MMAP, "nopage vma %p inode %lu, locking ["LPU64", "LPU64"]\n",
               vma, inode->i_ino, policy.l_extent.start, policy.l_extent.end);

        mode = mode_from_vma(vma);
        old_mtime = LTIME_S(inode->i_mtime);

        lsm = lli->lli_smd;
        rc = ll_extent_lock(fd, inode, lsm, mode, &policy,
                            &lockh, LDLM_FL_CBPENDING | LDLM_FL_NO_LRU);
        if (rc != 0)
                RETURN(NOPAGE_SIGBUS);

        if (vma->vm_flags & VM_EXEC && LTIME_S(inode->i_mtime) != old_mtime)
                CWARN("binary changed. inode %lu\n", inode->i_ino);

        lov_stripe_lock(lsm);
        inode_init_lvb(inode, &lvb);
        obd_merge_lvb(ll_i2obdexp(inode), lsm, &lvb, 1);
        kms = lvb.lvb_size;

        pgoff = ((address - vma->vm_start) >> CFS_PAGE_SHIFT) + vma->vm_pgoff;
        size = (kms + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;

        if (pgoff >= size) {
                lov_stripe_unlock(lsm);
                ll_glimpse_size(inode, LDLM_FL_BLOCK_GRANTED);
        } else {
                /* XXX change inode size without ll_inode_size_lock() held!
                 *     there is a race condition with truncate path. (see
                 *     ll_extent_lock) */
                /* XXX i_size_write() is not used because it is not safe to
                 *     take the ll_inode_size_lock() due to a potential lock
                 *     inversion (bug 6077).  And since it's not safe to use
                 *     i_size_write() without a covering mutex we do the
                 *     assignment directly.  It is not critical that the
                 *     size be correct. */
                /* NOTE: region is within kms and, hence, within real file size (A).
                 * We need to increase i_size to cover the read region so that
                 * generic_file_read() will do its job, but that doesn't mean
                 * the kms size is _correct_, it is only the _minimum_ size.
                 * If someone does a stat they will get the correct size which
                 * will always be >= the kms value here.  b=11081 */
                if (i_size_read(inode) < kms) {
                        inode->i_size = kms;
                        CDEBUG(D_INODE, "ino=%lu, updating i_size %llu\n",
                               inode->i_ino, i_size_read(inode));
                }
                lov_stripe_unlock(lsm);
        }

        /* If mapping is writeable, adjust kms to cover this page,
         * but do not extend kms beyond actual file size.
         * policy.l_extent.end is set to the end of the page by policy_from_vma
         * bug 10919 */
        lov_stripe_lock(lsm);
        if (mode == LCK_PW)
                obd_adjust_kms(ll_i2obdexp(inode), lsm,
                               min_t(loff_t, policy.l_extent.end + 1,
                               i_size_read(inode)), 0);
        lov_stripe_unlock(lsm);

        /* disable VM_SEQ_READ and use VM_RAND_READ to make sure that
         * the kernel will not read other pages not covered by ldlm in
         * filemap_nopage. we do our readahead in ll_readpage.
         */
        rand_read = vma->vm_flags & VM_RAND_READ;
        seq_read = vma->vm_flags & VM_SEQ_READ;
        vma->vm_flags &= ~ VM_SEQ_READ;
        vma->vm_flags |= VM_RAND_READ;

        page = filemap_nopage(vma, address, type);
        if (page != NOPAGE_SIGBUS && page != NOPAGE_OOM)
                LL_CDEBUG_PAGE(D_PAGE, page, "got addr %lu type %lx\n", address,
                               (long)type);
        else
                CDEBUG(D_PAGE, "got addr %lu type %lx - SIGBUS\n",  address,
                               (long)type);

        vma->vm_flags &= ~VM_RAND_READ;
        vma->vm_flags |= (rand_read | seq_read);

        ll_extent_unlock(fd, inode, ll_i2info(inode)->lli_smd, mode, &lockh);
        RETURN(page);
}

/* To avoid cancel the locks covering mmapped region for lock cache pressure,
 * we track the mapped vma count by lli_mmap_cnt.
 * ll_vm_open():  when first vma is linked, split locks from lru.
 * ll_vm_close(): when last vma is unlinked, join all this file's locks to lru.
 *
 * XXX we don't check the if the region of vma/lock for performance.
 */
static void ll_vm_open(struct vm_area_struct * vma)
{
        struct inode *inode = vma->vm_file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

        LASSERT(vma->vm_file);

        spin_lock(&lli->lli_lock);
        LASSERT(atomic_read(&lli->lli_mmap_cnt) >= 0);

        atomic_inc(&lli->lli_mmap_cnt);
        if (atomic_read(&lli->lli_mmap_cnt) == 1) {
                struct lov_stripe_md *lsm = lli->lli_smd;
                struct ll_sb_info *sbi = ll_i2sbi(inode);
                int count;

                spin_unlock(&lli->lli_lock);

                if (!lsm)
                        return;
                count = obd_join_lru(sbi->ll_osc_exp, lsm, 0);
                VMA_DEBUG(vma, "split %d unused locks from lru\n", count);
        } else {
                spin_unlock(&lli->lli_lock);
        }

}

static void ll_vm_close(struct vm_area_struct *vma)
{
        struct inode *inode = vma->vm_file->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

        LASSERT(vma->vm_file);

        spin_lock(&lli->lli_lock);
        LASSERT(atomic_read(&lli->lli_mmap_cnt) > 0);

        atomic_dec(&lli->lli_mmap_cnt);
        if (atomic_read(&lli->lli_mmap_cnt) == 0) {
                struct lov_stripe_md *lsm = lli->lli_smd;
                struct ll_sb_info *sbi = ll_i2sbi(inode);
                int count;

                spin_unlock(&lli->lli_lock);

                if (!lsm)
                        return;
                count = obd_join_lru(sbi->ll_osc_exp, lsm, 1);
                VMA_DEBUG(vma, "join %d unused locks to lru\n", count);
        } else {
                spin_unlock(&lli->lli_lock);
        }
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
#ifndef HAVE_FILEMAP_POPULATE
                if (!filemap_populate)
                        filemap_populate = vma->vm_ops->populate;
#endif
                vma->vm_ops = &ll_file_vm_ops;
                vma->vm_ops->open(vma);
                /* update the inode's size and mtime */
                rc = ll_glimpse_size(file->f_dentry->d_inode, 0);
        }

        RETURN(rc);
}
