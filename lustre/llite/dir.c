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
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/llite/dir.c
 *
 * Directory code for lustre client.
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>   // for wait_on_buffer

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lustre_lite.h>
#include <lustre_dlm.h>
#include "llite_internal.h"

#ifndef HAVE_PAGE_CHECKED
#ifdef HAVE_PG_FS_MISC
#define PageChecked(page)        test_bit(PG_fs_misc, &(page)->flags)
#define SetPageChecked(page)     set_bit(PG_fs_misc, &(page)->flags)
#else
#error PageChecked or PageFsMisc not defined in kernel
#endif
#endif

/* returns the page unlocked, but with a reference */
static int ll_dir_readpage(struct file *file, struct page *page)
{
        struct inode *inode = page->mapping->host;
        struct ll_fid mdc_fid;
        __u64 offset;
        struct ptlrpc_request *request;
        struct mds_body *body;
        int rc = 0;
        ENTRY;

        offset = (__u64)page->index << CFS_PAGE_SHIFT;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p) off "LPU64"\n",
               inode->i_ino, inode->i_generation, inode, offset);

        ll_pack_fid(&mdc_fid, inode->i_ino, inode->i_generation, S_IFDIR);

        rc = mdc_readpage(ll_i2sbi(inode)->ll_mdc_exp, &mdc_fid,
                          offset, page, &request);
        if (!rc) {
                body = lustre_msg_buf(request->rq_repmsg, REPLY_REC_OFF,
                                      sizeof(*body));
                LASSERT(body != NULL); /* checked by mdc_readpage() */
                /* swabbed by mdc_readpage() */
                LASSERT(lustre_rep_swabbed(request, REPLY_REC_OFF));

                if (body->size != i_size_read(inode)) {
                        ll_inode_size_lock(inode, 0);
                        i_size_write(inode, body->size);
                        ll_inode_size_unlock(inode, 0);
                }

                SetPageUptodate(page);
        }
        ptlrpc_req_finished(request);

        unlock_page(page);
        EXIT;
        return rc;
}

#ifndef MS_HAS_NEW_AOPS
struct address_space_operations ll_dir_aops = {
        .readpage  = ll_dir_readpage,
};
#else
struct address_space_operations_ext ll_dir_aops = {
        .orig_aops.readpage  = ll_dir_readpage,
};
#endif

static inline unsigned ll_dir_page_mask(struct inode *inode)
{
        return ~(inode->i_sb->s_blocksize - 1);
}

/*
 * Check consistency of a single entry.
 */
static int ll_dir_check_entry(struct inode *dir, struct ll_dir_entry *ent,
                              unsigned offset, unsigned rec_len, pgoff_t index)
{
        const char *msg;

        /*
         * Consider adding more checks.
         */

        if (unlikely(rec_len < ll_dir_rec_len(1)))
                msg = "entry is too short";
        else if (unlikely(rec_len & 3))
                msg = "wrong alignment";
        else if (unlikely(rec_len < ll_dir_rec_len(ent->lde_name_len)))
                msg = "rec_len doesn't match name_len";
        else if (unlikely(((offset + rec_len - 1) ^ offset) &
                          ll_dir_page_mask(dir)))
                msg = "directory entry across blocks";
        else
                return 0;
        CERROR("%s: bad entry in directory %lu/%u: %s - "
               "offset=%lu+%u, inode=%lu, rec_len=%d,"
               " name_len=%d\n", ll_i2mdcexp(dir)->exp_obd->obd_name,
               dir->i_ino, dir->i_generation, msg,
               index << CFS_PAGE_SHIFT,
               offset, (unsigned long)le32_to_cpu(ent->lde_inode),
               rec_len, ent->lde_name_len);
        return -EIO;
}

static void ll_dir_check_page(struct inode *dir, struct page *page)
{
        int      err;
        unsigned size = dir->i_sb->s_blocksize;
        char    *addr = page_address(page);
        unsigned off;
        unsigned limit;
        unsigned reclen;

        struct ll_dir_entry *ent;

        err = 0;
        if ((i_size_read(dir) >> CFS_PAGE_SHIFT) == (__u64)page->index) {
                /*
                 * Last page.
                 */
                limit = i_size_read(dir) & ~CFS_PAGE_MASK;
                if (limit & (size - 1)) {
                        CERROR("%s: dir %lu/%u size %llu doesn't match %u\n",
                               ll_i2mdcexp(dir)->exp_obd->obd_name, dir->i_ino,
                               dir->i_generation, i_size_read(dir), size);
                        err++;
                } else {
                        /*
                         * Place dummy forwarding entries to streamline
                         * ll_readdir().
                         */
                        for (off = limit; off < CFS_PAGE_SIZE; off += size) {
                                ent = ll_entry_at(addr, off);
                                ent->lde_rec_len = cpu_to_le16(size);
                                ent->lde_name_len = 0;
                                ent->lde_inode = 0;
                        }
                }
        } else
                limit = CFS_PAGE_SIZE;

        for (off = 0;
             !err && off <= limit - ll_dir_rec_len(1); off += reclen) {
                ent    = ll_entry_at(addr, off);
                reclen = le16_to_cpu(ent->lde_rec_len);
                err    = ll_dir_check_entry(dir, ent, off, reclen, page->index);
        }

        if (!err && off != limit) {
                ent = ll_entry_at(addr, off);
                CERROR("%s: entry in directory %lu/%u spans the page boundary "
                       "offset="LPU64"+%u, inode=%lu\n",
                       ll_i2mdcexp(dir)->exp_obd->obd_name,
                       dir->i_ino, dir->i_generation,
                       (__u64)page->index << CFS_PAGE_SHIFT,
                       off, (unsigned long)le32_to_cpu(ent->lde_inode));
                err++;
        }
        if (err)
                SetPageError(page);
        SetPageChecked(page);
}

struct page *ll_get_dir_page(struct inode *dir, unsigned long n)
{
        struct ldlm_res_id res_id;
        struct lustre_handle lockh;
        struct obd_device *obddev = class_exp2obd(ll_i2sbi(dir)->ll_mdc_exp);
        struct address_space *mapping = dir->i_mapping;
        struct page *page;
        ldlm_policy_data_t policy = {.l_inodebits = {MDS_INODELOCK_UPDATE} };
        int rc;

        fid_build_reg_res_name(ll_inode_lu_fid(dir), &res_id);
        rc = ldlm_lock_match(obddev->obd_namespace, LDLM_FL_BLOCK_GRANTED,
                             &res_id, LDLM_IBITS, &policy, LCK_CR, &lockh);
        if (!rc) {
                struct lookup_intent it = { .it_op = IT_READDIR };
                struct ldlm_enqueue_info einfo = { LDLM_IBITS, LCK_CR,
                       ll_mdc_blocking_ast, ldlm_completion_ast, NULL, dir };
                struct ptlrpc_request *request;
                struct mdc_op_data data = { { 0 } };

                ll_prepare_mdc_op_data(&data, dir, NULL, NULL, 0, 0, NULL);

                rc = mdc_enqueue(ll_i2sbi(dir)->ll_mdc_exp, &einfo, &it,
                                 &data, &lockh, NULL, 0, 0);

                request = (struct ptlrpc_request *)it.d.lustre.it_data;
                if (request)
                        ptlrpc_req_finished(request);
                if (rc < 0) {
                        CERROR("lock enqueue: rc: %d\n", rc);
                        return ERR_PTR(rc);
                }
        }
        ldlm_lock_dump_handle(D_OTHER, &lockh);

        page = read_cache_page(mapping, n,
                               (filler_t*)mapping->a_ops->readpage, NULL);
        if (IS_ERR(page))
                GOTO(out_unlock, page);

        wait_on_page(page);
        (void)kmap(page);
        if (!PageUptodate(page))
                goto fail;
        if (!PageChecked(page))
                ll_dir_check_page(dir, page);
        if (PageError(page))
                goto fail;

out_unlock:
        ldlm_lock_decref(&lockh, LCK_CR);
        return page;

fail:
        ll_put_page(page);
        page = ERR_PTR(-EIO);
        goto out_unlock;
}

static inline unsigned ll_dir_validate_entry(char *base, unsigned offset,
                                             unsigned mask)
{
        struct ll_dir_entry *de = ll_entry_at(base, offset);
        struct ll_dir_entry *p  = ll_entry_at(base, offset & mask);
        while (p < de && p->lde_rec_len > 0)
                p = ll_dir_next_entry(p);
        return (char *)p - base;
}

/*
 * File type constants. The same as in ext2 for compatibility.
 */

enum {
        LL_DIR_FT_UNKNOWN,
        LL_DIR_FT_REG_FILE,
        LL_DIR_FT_DIR,
        LL_DIR_FT_CHRDEV,
        LL_DIR_FT_BLKDEV,
        LL_DIR_FT_FIFO,
        LL_DIR_FT_SOCK,
        LL_DIR_FT_SYMLINK,
        LL_DIR_FT_MAX
};

static unsigned char ll_dir_filetype_table[LL_DIR_FT_MAX] = {
        [LL_DIR_FT_UNKNOWN]  = DT_UNKNOWN,
        [LL_DIR_FT_REG_FILE] = DT_REG,
        [LL_DIR_FT_DIR]      = DT_DIR,
        [LL_DIR_FT_CHRDEV]   = DT_CHR,
        [LL_DIR_FT_BLKDEV]   = DT_BLK,
        [LL_DIR_FT_FIFO]     = DT_FIFO,
        [LL_DIR_FT_SOCK]     = DT_SOCK,
        [LL_DIR_FT_SYMLINK]  = DT_LNK,
};

/*
 * Process one page. Returns:
 *
 *     -ve: filldir commands readdir to stop.
 *     +ve: number of entries submitted to filldir.
 *       0: no live entries on this page.
 */

static int ll_readdir_page(char *addr, __u64 base, unsigned *offset,
                           filldir_t filldir, void *cookie)
{
        struct ll_dir_entry *de;
        char *end;
        int nr;

        de = ll_entry_at(addr, *offset);
        end = addr + CFS_PAGE_SIZE - ll_dir_rec_len(1);
        for (nr = 0 ;(char*)de <= end; de = ll_dir_next_entry(de)) {
                if (de->lde_inode != 0) {
                        nr++;
                        *offset = (char *)de - addr;
                        if (filldir(cookie, de->lde_name, de->lde_name_len,
                                    base | *offset, le32_to_cpu(de->lde_inode),
                                    ll_dir_filetype_table[de->lde_file_type &
                                                          (LL_DIR_FT_MAX - 1)]))
                                return -1;
                }
        }
        return nr;
}

static int ll_readdir_18(struct file *filp, void *dirent, filldir_t filldir)
{
        struct inode *inode = filp->f_dentry->d_inode;
        loff_t pos          = filp->f_pos;
        unsigned offset     = pos & ~CFS_PAGE_MASK;
        pgoff_t idx         = pos >> CFS_PAGE_SHIFT;
        pgoff_t npages      = dir_pages(inode);
        unsigned chunk_mask = ll_dir_page_mask(inode);
        int need_revalidate = (filp->f_version == 0 ||
                               filp->f_version != inode->i_version);
        int rc              = 0;
        int done; /* when this becomes negative --- stop iterating */

        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p) pos %llu/%llu\n",
               inode->i_ino, inode->i_generation, inode,
               pos, i_size_read(inode));

        /*
         * Checking ->i_size without the lock. Should be harmless, as server
         * re-checks.
         */
        if (pos > i_size_read(inode) - ll_dir_rec_len(1))
                RETURN(0);

        for (done = 0; idx < npages; idx++, offset = 0) {
                /*
                 * We can assume that all blocks on this page are filled with
                 * entries, because ll_dir_check_page() placed special dummy
                 * entries for us.
                 */

                char *kaddr;
                struct page *page;

                CDEBUG(D_EXT2,"read %lu of dir %lu/%u page %lu/%lu "
                       "size %llu\n",
                       CFS_PAGE_SIZE, inode->i_ino, inode->i_generation,
                       idx, npages, i_size_read(inode));
                page = ll_get_dir_page(inode, idx);

                /* size might have been updated by mdc_readpage */
                npages = dir_pages(inode);

                if (IS_ERR(page)) {
                        rc = PTR_ERR(page);
                        CERROR("error reading dir %lu/%u page %lu: rc %d\n",
                               inode->i_ino, inode->i_generation, idx, rc);
                        continue;
                }

                kaddr = page_address(page);
                if (need_revalidate) {
                        /*
                         * File offset was changed by lseek() and possibly
                         * points in the middle of an entry. Re-scan from the
                         * beginning of the chunk.
                         */
                        offset = ll_dir_validate_entry(kaddr, offset,
                                                       chunk_mask);
                        need_revalidate = 0;
                }
                done = ll_readdir_page(kaddr, idx << CFS_PAGE_SHIFT,
                                       &offset, filldir, dirent);
                ll_put_page(page);
                if (done > 0)
                        /*
                         * Some entries were sent to the user space, return
                         * success.
                         */
                        rc = 0;
                else if (done < 0)
                        /*
                         * filldir is satisfied.
                         */
                        break;
        }

        filp->f_pos = (idx << CFS_PAGE_SHIFT) | offset;
        filp->f_version = inode->i_version;
        touch_atime(filp->f_vfsmnt, filp->f_dentry);

        RETURN(rc);
}

/*      
 * Chain of hash overflow pages.
 */            
struct ll_dir_chain {
        /* XXX something. Later */
};
  
static inline void ll_dir_chain_init(struct ll_dir_chain *chain)
{  
}

static inline void ll_dir_chain_fini(struct ll_dir_chain *chain)
{
}

static inline unsigned long hash_x_index(__u64 hash, int hash64)
{
#ifdef __KERNEL__
        if (BITS_PER_LONG == 32 && hash64)
                hash >>= 32;
#endif
        return ~0UL - hash;
}

/**
 * Layout of readdir pages, as transmitted on wire.
 */
struct lu_dirent {
        /** valid if LUDA_FID is set. */
        struct lu_fid lde_fid;
        /** a unique entry identifier: a hash or an offset. */
        __u64         lde_hash;
        /** total record length, including all attributes. */
        __u16         lde_reclen;
        /** name length */
        __u16         lde_namelen;
        /** optional variable size attributes following this entry.
         *  taken from enum lu_dirent_attrs.
         */
        __u32         lde_attrs;
        /** name is followed by the attributes indicated in ->ldp_attrs, in
         *  their natural order. After the last attribute, padding bytes are
         *  added to make ->lde_reclen a multiple of 8.
         */
        char          lde_name[0];
};

struct lu_dirpage {
        __u64            ldp_hash_start;
        __u64            ldp_hash_end;
        __u16            ldp_flags;
        __u16            ldp_pad0;
        __u32            ldp_pad1;
        struct lu_dirent ldp_entries[0];
};

/*
 * Definitions of optional directory entry attributes formats.
 *
 * Individual attributes do not have their length encoded in a generic way. It
 * is assumed that consumer of an attribute knows its format. This means that
 * it is impossible to skip over an unknown attribute, except by skipping over all
 * remaining attributes (by using ->lde_reclen), which is not too
 * constraining, because new server versions will append new attributes at
 * the end of an entry.
 */

/**
 * Fid directory attribute: a fid of an object referenced by the entry. This
 * will be almost always requested by the client and supplied by the server.
 *
 * Aligned to 8 bytes.
 */
/* To have compatibility with 1.8, lets have fid in lu_dirent struct. */

/**
 * File type.
 *
 * Aligned to 2 bytes.
 */
struct luda_type {
        __u16 lt_type;
};

enum lu_dirpage_flags {
        LDF_EMPTY = 1 << 0
};

static inline int lu_dirent_calc_size(int namelen, __u16 attr)
{
        int size;

        if (attr & LUDA_TYPE) {
                const unsigned align = sizeof(struct luda_type) - 1;
                size = (sizeof(struct lu_dirent) + namelen + align) & ~align;
                size += sizeof(struct luda_type);
        } else
                size = sizeof(struct lu_dirent) + namelen;

        return (size + 7) & ~7;
}

/**
 * return IF_* type for given lu_dirent entry.
 * IF_* flag shld be converted to particular OS file type in
 * platform llite module.
 */
__u16 ll_dirent_type_get(struct lu_dirent *ent)
{
        __u16 type = 0;
        struct luda_type *lt;
        int len = 0;

        if (le32_to_cpu(ent->lde_attrs) & LUDA_TYPE) {
                const unsigned align = sizeof(struct luda_type) - 1;

                len = le16_to_cpu(ent->lde_namelen);
                len = (len + align) & ~align;
                lt = (void *) ent->lde_name + len;
                type = CFS_IFTODT(le16_to_cpu(lt->lt_type));
        }
        return type;
}

static inline struct lu_dirent *lu_dirent_start(struct lu_dirpage *dp)
{
        if (le16_to_cpu(dp->ldp_flags) & LDF_EMPTY)
                return NULL;
        else
                return dp->ldp_entries;
}

static inline struct lu_dirent *lu_dirent_next(struct lu_dirent *ent)
{
        struct lu_dirent *next;

        if (le16_to_cpu(ent->lde_reclen) != 0)
                next = ((void *)ent) + le16_to_cpu(ent->lde_reclen);
        else
                next = NULL;

        return next;
}

static inline int lu_dirent_size(struct lu_dirent *ent)
{
        if (le16_to_cpu(ent->lde_reclen) == 0) {
                return lu_dirent_calc_size(le16_to_cpu(ent->lde_namelen),
                                           le32_to_cpu(ent->lde_attrs));
        }
        return le16_to_cpu(ent->lde_reclen);
}

#ifdef HAVE_RW_TREE_LOCK
#define TREE_READ_LOCK_IRQ(mapping)     read_lock_irq(&(mapping)->tree_lock)
#define TREE_READ_UNLOCK_IRQ(mapping) read_unlock_irq(&(mapping)->tree_lock)
#else
#define TREE_READ_LOCK_IRQ(mapping) spin_lock_irq(&(mapping)->tree_lock)
#define TREE_READ_UNLOCK_IRQ(mapping) spin_unlock_irq(&(mapping)->tree_lock)
#endif

/* returns the page unlocked, but with a reference */
static int ll_dir_readpage_20(struct file *file, struct page *page)
{
        struct inode *inode = page->mapping->host;
        struct ptlrpc_request *request;
        struct mdt_body *body;
        struct ll_fid fid;
        __u64 hash;
        int rc;
        ENTRY;

        /*XXX: statahead is disabled by force under interoperability mode.
         *     So file must not be NULL here. Fix me when enable statahead
         *     under interoperability mode. */
        LASSERT(file != NULL);
        hash = ((struct ll_file_data *)LUSTRE_FPRIVATE(file))->fd_dir.lfd_next;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p) off %lu\n",
               inode->i_ino, inode->i_generation, inode, (unsigned long)hash);

        ll_inode2fid(&fid, inode);
        rc = mdc_readpage(ll_i2sbi(inode)->ll_mdc_exp, &fid,
                          hash, page, &request);
        if (!rc) {
                body = lustre_msg_buf(request->rq_repmsg, REPLY_REC_OFF,
                                      sizeof(*body));
                /* Checked by mdc_readpage() */
                LASSERT(body != NULL);

                if (body->valid & OBD_MD_FLSIZE) {
                        ll_inode_size_lock(inode, 0);
                        i_size_write(inode, body->size);
                        ll_inode_size_unlock(inode, 0);
                }
                SetPageUptodate(page);
        }
        ptlrpc_req_finished(request);

        unlock_page(page);
        EXIT;
        return rc;
}


static void ll_check_page(struct inode *dir, struct page *page)
{
        /* XXX: check page format later */
        SetPageChecked(page);
}


/*
 * Find, kmap and return page that contains given hash.
 */
static struct page *ll_dir_page_locate(struct inode *dir, __u64 *hash,
                                       __u64 *start, __u64 *end)
{
        int hash64 = ll_i2sbi(dir)->ll_flags & LL_SBI_64BIT_HASH;
        struct address_space *mapping = dir->i_mapping;
        /*
         * Complement of hash is used as an index so that
         * radix_tree_gang_lookup() can be used to find a page with starting
         * hash _smaller_ than one we are looking for.
         */
        unsigned long offset = hash_x_index(*hash, hash64);
        struct page *page;
        int found;
        ENTRY;

        TREE_READ_LOCK_IRQ(mapping);
        found = radix_tree_gang_lookup(&mapping->page_tree,
                                       (void **)&page, offset, 1);
        if (found > 0) {
                struct lu_dirpage *dp;

                page_cache_get(page);
                TREE_READ_UNLOCK_IRQ(mapping);
                /*
                 * In contrast to find_lock_page() we are sure that directory
                 * page cannot be truncated (while DLM lock is held) and,
                 * hence, can avoid restart.
                 *
                 * In fact, page cannot be locked here at all, because
                 * ll_dir_readpage() does synchronous io.
                 */
                wait_on_page(page);
                if (PageUptodate(page)) {
                        dp = kmap(page);
                        if (BITS_PER_LONG == 32 && hash64) {
                                *start = le64_to_cpu(dp->ldp_hash_start) >> 32;
                                *end   = le64_to_cpu(dp->ldp_hash_end) >> 32;
                                *hash  = *hash >> 32;
                        } else {
                                *start = le64_to_cpu(dp->ldp_hash_start);
                                *end   = le64_to_cpu(dp->ldp_hash_end);
                        }
                        LASSERTF(*start <= *hash, "start = "LPX64",end = "
                                 LPX64",hash = "LPX64"\n", *start, *end, *hash);
                        if (*hash > *end || (*end != *start && *hash == *end)) {
                                kunmap(page);
                                lock_page(page);
                                truncate_complete_page(page->mapping, page);
                                unlock_page(page);
                                page_cache_release(page);
                                page = NULL;
                        }
                } else {
                        page_cache_release(page);
                        page = ERR_PTR(-EIO);
                }

        } else {
                TREE_READ_UNLOCK_IRQ(mapping);
                page = NULL;
        }
        RETURN(page);
}

static struct page *ll_get_dir_page_20(struct file *filp, struct inode *dir,
                                       __u64 hash, int exact,
                                       struct ll_dir_chain *chain)
{
        struct ldlm_res_id res_id;
        struct lustre_handle lockh;
        struct obd_device *obddev = class_exp2obd(ll_i2sbi(dir)->ll_mdc_exp);
        struct address_space *mapping = dir->i_mapping;
        struct lu_dirpage *dp;
        struct page *page;
        ldlm_policy_data_t policy = {.l_inodebits = {MDS_INODELOCK_UPDATE} };
        ldlm_mode_t mode;
        int rc;
        __u64 start = 0;
        __u64 end = 0;
        __u64 lhash = hash;
        int hash64 = ll_i2sbi(dir)->ll_flags & LL_SBI_64BIT_HASH;
        ENTRY;
 
        fid_build_reg_res_name(ll_inode_lu_fid(dir), &res_id);
        mode = LCK_PR;
        rc = ldlm_lock_match(obddev->obd_namespace, LDLM_FL_BLOCK_GRANTED,
                             &res_id, LDLM_IBITS, &policy, mode, &lockh);
        if (!rc) {
                struct lookup_intent it = { .it_op = IT_READDIR };
                struct ldlm_enqueue_info einfo = { LDLM_IBITS, mode,
                       ll_mdc_blocking_ast, ldlm_completion_ast, NULL, dir };
                struct ptlrpc_request *request;
                struct mdc_op_data op_data = { { 0 } };

                ll_prepare_mdc_op_data(&op_data, dir, NULL, NULL, 0, 0, NULL);

                rc = mdc_enqueue(ll_i2sbi(dir)->ll_mdc_exp, &einfo, &it,
                                 &op_data, &lockh, NULL, 0, 0);

                request = (struct ptlrpc_request *)it.d.lustre.it_data;
                if (request)
                        ptlrpc_req_finished(request);
                if (rc < 0) {
                        CERROR("lock enqueue: rc: %d\n", rc);
                        RETURN(ERR_PTR(rc));
                }
        }
        ldlm_lock_dump_handle(D_OTHER, &lockh);

        page = ll_dir_page_locate(dir, &lhash, &start, &end);
        if (IS_ERR(page))
                GOTO(out_unlock, page);

        if (page != NULL) {
                /*
                 * XXX nikita: not entirely correct handling of a corner case:
                 * suppose hash chain of entries with hash value HASH crosses
                 * border between pages P0 and P1. First both P0 and P1 are
                 * cached, seekdir() is called for some entry from the P0 part
                 * of the chain. Later P0 goes out of cache. telldir(HASH)
                 * happens and finds P1, as it starts with matching hash
                 * value. Remaining entries from P0 part of the chain are
                 * skipped. (Is that really a bug?)
                 *
                 * Possible solutions: 0. don't cache P1 is such case, handle
                 * it as an "overflow" page. 1. invalidate all pages at
                 * once. 2. use HASH|1 as an index for P1.
                 */
                if (exact && hash != start) {
                        /*
                         * readdir asked for a page starting _exactly_ from
                         * given hash, but cache contains stale page, with
                         * entries with smaller hash values. Stale page should
                         * be invalidated, and new one fetched.
                         */
                        CDEBUG(D_INFO, "Stale readpage page %p: %#lx != %#lx\n",
                              page, (unsigned long)lhash, (unsigned long)start);
                        lock_page(page);
                        truncate_complete_page(page->mapping, page);
                        unlock_page(page);
                        page_cache_release(page);
                } else {
                        GOTO(hash_collision, page);
                }
        }

        page = read_cache_page(mapping, hash_x_index(hash, hash64),
                               (filler_t*)ll_dir_readpage_20, filp);
        if (IS_ERR(page))
                GOTO(out_unlock, page);

        wait_on_page(page);
        (void)kmap(page);
        if (!PageUptodate(page))
                goto fail;
        if (!PageChecked(page))
                ll_check_page(dir, page);
        if (PageError(page))
                goto fail;
hash_collision:
        dp = page_address(page);

        if (BITS_PER_LONG == 32 && hash64) {
                start = le64_to_cpu(dp->ldp_hash_start) >> 32;
                end   = le64_to_cpu(dp->ldp_hash_end) >> 32;
                lhash = hash >> 32;
        } else {
                start = le64_to_cpu(dp->ldp_hash_start);
                end   = le64_to_cpu(dp->ldp_hash_end);
                lhash = hash;
        }
        if (end == start) {
                LASSERT(start == lhash);
                CWARN("Page-wide hash collision: "LPU64"\n", end);
                if (BITS_PER_LONG == 32 && hash64)
                        CWARN("Real page-wide hash collision at ["LPU64" "LPU64
                              "] with hash "LPU64"\n",
                              le64_to_cpu(dp->ldp_hash_start),
                              le64_to_cpu(dp->ldp_hash_end), hash);
                /*
                 * Fetch whole overflow chain...
                 *
                 * XXX not yet.
                 */
                goto fail;
        }
out_unlock:
        ldlm_lock_decref(&lockh, mode);
        RETURN(page);

fail:
        ll_put_page(page);
        page = ERR_PTR(-EIO);
        goto out_unlock;
}

static int ll_readdir_20(struct file *filp, void *cookie, filldir_t filldir)
{
        struct inode         *inode = filp->f_dentry->d_inode;
        struct ll_sb_info    *sbi   = ll_i2sbi(inode);
        struct ll_file_data  *fd    = LUSTRE_FPRIVATE(filp);
        __u64                 pos   = fd->fd_dir.lfd_pos;
        int                   api32 = ll_need_32bit_api(sbi);
        int                   hash64= sbi->ll_flags & LL_SBI_64BIT_HASH;
        struct page          *page;
        struct ll_dir_chain   chain;
        int                   rc;
        int                   done;
        int                   shift;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p) pos %lu/%llu 32bit_api %d\n",
               inode->i_ino, inode->i_generation, inode,
               (unsigned long)pos, i_size_read(inode), api32);

        if (pos == MDS_DIR_END_OFF)
                /*
                 * end-of-file.
                 */
                RETURN(0);

        rc    = 0;
        done  = 0;
        shift = 0;
        ll_dir_chain_init(&chain);

        fd->fd_dir.lfd_next = pos;
        page = ll_get_dir_page_20(filp, inode, pos, 0, &chain);


        while (rc == 0 && !done) {
                struct lu_dirpage *dp;
                struct lu_dirent  *ent;

                if (!IS_ERR(page)) {
                        /* 
                         * If page is empty (end of directoryis reached),
                         * use this value. 
                         */
                        __u64 hash = MDS_DIR_END_OFF;
                        __u64 next;

                        dp = page_address(page);
                        for (ent = lu_dirent_start(dp); ent != NULL && !done;
                             ent = lu_dirent_next(ent)) {
                                __u16          type;
                                int            namelen;
                                struct lu_fid  fid;
                                __u64          lhash;
                                __u64          ino;

                                hash = le64_to_cpu(ent->lde_hash);
                                if (hash < pos)
                                        /*
                                         * Skip until we find target hash
                                         * value.
                                         */
                                        continue;

                                namelen = le16_to_cpu(ent->lde_namelen);
                                if (namelen == 0)
                                        /*
                                         * Skip dummy record.
                                         */
                                        continue;

                                fid_le_to_cpu(&fid, &ent->lde_fid);
                                ino = ll_fid_build_ino((struct ll_fid *)&fid,
                                                       api32);
                                if (api32 && hash64)
                                        lhash = hash >> 32;
                                else
                                        lhash = hash;
                                type = ll_dirent_type_get(ent);
                                done = filldir(cookie, ent->lde_name, namelen,
                                               lhash, ino, type);
                        }
                        next = le64_to_cpu(dp->ldp_hash_end);
                        ll_put_page(page);
                        if (!done) {
                                pos = next;
                                if (pos == MDS_DIR_END_OFF) {
                                        /*
                                         * End of directory reached.
                                         */
                                        done = 1;
                                } else if (1 /* chain is exhausted*/) {
                                        /*
                                         * Normal case: continue to the next
                                         * page.
                                         */
                                        fd->fd_dir.lfd_next = pos;
                                        page = ll_get_dir_page_20(filp, inode,
                                                                  pos, 1,
                                                                  &chain);
                                } else {
                                        /*
                                         * go into overflow page.
                                         */
                                }
                        } else {
                                pos = hash;
                        }
                } else {
                        rc = PTR_ERR(page);
                        CERROR("error reading dir "DFID" at %lu: rc %d\n",
                               PFID(ll_inode_lu_fid(inode)),
                               (unsigned long)pos, rc);
                }
        }

        fd->fd_dir.lfd_pos = pos;
        if (pos == MDS_DIR_END_OFF) {
                if (api32)
                        filp->f_pos = LL_DIR_END_OFF_32BIT;
                else
                        filp->f_pos = LL_DIR_END_OFF;
        } else {
                if (api32 && hash64)
                        filp->f_pos = pos >> 32;
                else
                        filp->f_pos = pos;
        }
        filp->f_version = inode->i_version;
        touch_atime(filp->f_vfsmnt, filp->f_dentry);

        ll_dir_chain_fini(&chain);

        RETURN(rc);
}

static int ll_readdir(struct file *filp, void *cookie, filldir_t filldir)
{
        struct inode      *inode = filp->f_dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);

        if (sbi->ll_mdc_exp->exp_connect_flags & OBD_CONNECT_FID) {
                return ll_readdir_20(filp, cookie, filldir);
        } else {
                return ll_readdir_18(filp, cookie, filldir);
        }
}

#define QCTL_COPY(out, in)              \
do {                                    \
        Q_COPY(out, in, qc_cmd);        \
        Q_COPY(out, in, qc_type);       \
        Q_COPY(out, in, qc_id);         \
        Q_COPY(out, in, qc_stat);       \
        Q_COPY(out, in, qc_dqinfo);     \
        Q_COPY(out, in, qc_dqblk);      \
} while (0)

static int ll_send_mgc_param(struct obd_export *mgc, char *string)
{
        struct mgs_send_param *msp;
        int rc = 0;

        OBD_ALLOC_PTR(msp);
        if (!msp)
                return -ENOMEM;

        strncpy(msp->mgs_param, string, MGS_PARAM_MAXLEN);
        rc = obd_set_info_async(mgc, sizeof(KEY_SET_INFO), KEY_SET_INFO,
                                sizeof(struct mgs_send_param), msp, NULL);
        if (rc)
                CERROR("Failed to set parameter: %d\n", rc);

        OBD_FREE_PTR(msp);
        return rc;
}

static char *ll_get_fsname(struct inode *inode)
{
        struct lustre_sb_info *lsi = s2lsi(inode->i_sb);
        char *ptr, *fsname;
        int len;

        OBD_ALLOC(fsname, MGS_PARAM_MAXLEN);
        len = strlen(lsi->lsi_lmd->lmd_profile);
        ptr = strrchr(lsi->lsi_lmd->lmd_profile, '-');
        if (ptr && (strcmp(ptr, "-client") == 0))
                len -= 7;
        strncpy(fsname, lsi->lsi_lmd->lmd_profile, len);
        fsname[len] = '\0';

        return fsname;
}

int ll_dir_setstripe(struct inode *inode, struct lov_user_md *lump,
                     int set_default)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct mdc_op_data data = { { 0 } };
        struct ptlrpc_request *req = NULL;
        struct lustre_sb_info *lsi = s2lsi(inode->i_sb);
        struct obd_device *mgc = lsi->lsi_mgc;
        char *fsname = NULL, *param = NULL;
        struct iattr attr = { 0 };
        int lum_size = 0, rc = 0;

        if (lump != NULL) {
                if (lump->lmm_magic == LOV_USER_MAGIC_V3)
                        lum_size = sizeof(struct lov_user_md_v3);
                else
                        lum_size = sizeof(struct lov_user_md_v1);
                /*
                 * This is coming from userspace, so should be in
                 * local endian.  But the MDS would like it in little
                 * endian, so we swab it before we send it.
                 */
                if ((lump->lmm_magic != cpu_to_le32(LOV_USER_MAGIC_V1)) &&
                    (lump->lmm_magic != cpu_to_le32(LOV_USER_MAGIC_V3))) {
                        rc = lustre_swab_lov_user_md(lump);
                        if (rc) 
                                return rc;
                }
        } else { /* NULL value means remove LOV EA */
                lum_size = sizeof(struct lov_user_md_v1);
        }

        ll_prepare_mdc_op_data(&data, inode, NULL, NULL, 0, 0, NULL);

        /* swabbing is done in lov_setstripe() on server side */
        rc = mdc_setattr(sbi->ll_mdc_exp, &data,
                         &attr, lump, lum_size, NULL, 0, &req);
        if (rc) {
                ptlrpc_req_finished(req);
                if (rc != -EPERM && rc != -EACCES)
                        CERROR("mdc_setattr fails: rc = %d\n", rc);
                return rc;
        }
        ptlrpc_req_finished(req);

        /* In the following we use the fact that LOV_USER_MAGIC_V1 and
         LOV_USER_MAGIC_V3 have the same initial fields so we do not
         need the make the distiction between the 2 versions */
        if (set_default && mgc->u.cli.cl_mgc_mgsexp) {
                OBD_ALLOC(param, MGS_PARAM_MAXLEN);

                /* Get fsname and assume devname to be -MDT0000. */
                fsname = ll_get_fsname(inode);
                /* Set root stripesize */
                sprintf(param, "%s-MDT0000.lov.stripesize=%u", fsname,
                        lump ? le32_to_cpu(lump->lmm_stripe_size) : 0);
                rc = ll_send_mgc_param(mgc->u.cli.cl_mgc_mgsexp, param);
                if (rc)
                        goto end;

                /* Set root stripecount */
                sprintf(param, "%s-MDT0000.lov.stripecount=%u", fsname,
                        lump ? le16_to_cpu(lump->lmm_stripe_count) : 0);
                rc = ll_send_mgc_param(mgc->u.cli.cl_mgc_mgsexp, param);
                if (rc)
                        goto end;

                /* Set root stripeoffset */
                sprintf(param, "%s-MDT0000.lov.stripeoffset=%u", fsname,
                        lump ? le16_to_cpu(lump->lmm_stripe_offset) :
                        (typeof(lump->lmm_stripe_offset))(-1));
                rc = ll_send_mgc_param(mgc->u.cli.cl_mgc_mgsexp, param);
                if (rc)
                        goto end;
end:
                if (fsname)
                        OBD_FREE(fsname, MGS_PARAM_MAXLEN);
                if (param)
                        OBD_FREE(param, MGS_PARAM_MAXLEN);
        }
        return rc;
}

int ll_dir_getstripe(struct inode *inode, struct lov_mds_md **lmmp,
                     int *lmm_size, struct ptlrpc_request **request)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_fid     fid;
        struct mds_body   *body;
        struct lov_mds_md *lmm = NULL;
        struct ptlrpc_request *req = NULL;
        int rc, lmmsize;

        ll_inode2fid(&fid, inode);

        rc = ll_get_max_mdsize(sbi, &lmmsize);
        if (rc)
                RETURN(rc);

        rc = mdc_getattr(sbi->ll_mdc_exp, &fid,
                        OBD_MD_FLEASIZE|OBD_MD_FLDIREA,
                        lmmsize, &req);
        if (rc < 0) {
                CDEBUG(D_INFO, "mdc_getattr failed on inode "
                       "%lu/%u: rc %d\n", inode->i_ino,
                       inode->i_generation, rc);
                GOTO(out, rc);
        }
        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                        sizeof(*body));
        LASSERT(body != NULL); /* checked by mdc_getattr_name */
        /* swabbed by mdc_getattr_name */
        LASSERT(lustre_rep_swabbed(req, REPLY_REC_OFF));

        lmmsize = body->eadatasize;

        if (!(body->valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) ||
            lmmsize == 0) {
                GOTO(out, rc = -ENODATA);
        }

        lmm = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 1, lmmsize);
        LASSERT(lmm != NULL);
        LASSERT(lustre_rep_swabbed(req, REPLY_REC_OFF + 1));

        /*
         * This is coming from the MDS, so is probably in
         * little endian.  We convert it to host endian before
         * passing it to userspace.
         */
        /* We don't swab objects for directories */
        if (((le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_V1) ||
            (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC_V3)) &&
            (LOV_MAGIC != cpu_to_le32(LOV_MAGIC))) {
                rc = lustre_swab_lov_user_md((struct lov_user_md*)lmm);
                if (rc)
                        GOTO(out, rc);
        }

out:
        *lmmp = lmm;
        *lmm_size = lmmsize;
        *request = req;
        return rc;
}

static int ll_dir_ioctl(struct inode *inode, struct file *file,
                        unsigned int cmd, unsigned long arg)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct obd_ioctl_data *data;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), cmd=%#x\n",
               inode->i_ino, inode->i_generation, inode, cmd);

        /* asm-ppc{,64} declares TCGETS, et. al. as type 't' not 'T' */
        if (_IOC_TYPE(cmd) == 'T' || _IOC_TYPE(cmd) == 't') /* tty ioctls */
                return -ENOTTY;

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_IOCTL, 1);
        switch(cmd) {
        case FSFILT_IOC_GETFLAGS:
        case FSFILT_IOC_SETFLAGS:
                RETURN(ll_iocontrol(inode, file, cmd, arg));
        case FSFILT_IOC_GETVERSION_OLD:
        case FSFILT_IOC_GETVERSION:
                RETURN(put_user(inode->i_generation, (int *)arg));
        /* We need to special case any other ioctls we want to handle,
         * to send them to the MDS/OST as appropriate and to properly
         * network encode the arg field.
        case EXT3_IOC_SETVERSION_OLD:
        case EXT3_IOC_SETVERSION:
        */
        case IOC_MDC_LOOKUP: {
                struct ptlrpc_request *request = NULL;
                struct ll_fid fid;
                char *buf = NULL;
                char *filename;
                int namelen, rc, len = 0;

                rc = obd_ioctl_getdata(&buf, &len, (void *)arg);
                if (rc)
                        RETURN(rc);
                data = (void *)buf;

                filename = data->ioc_inlbuf1;
                namelen = data->ioc_inllen1;

                if (namelen < 1) {
                        CDEBUG(D_INFO, "IOC_MDC_LOOKUP missing filename\n");
                        GOTO(out, rc = -EINVAL);
                }

                ll_inode2fid(&fid, inode);
                rc = mdc_getattr_name(sbi->ll_mdc_exp, &fid, filename, namelen,
                                      OBD_MD_FLID, 0, &request);
                if (rc < 0) {
                        CDEBUG(D_INFO, "mdc_getattr_name: %d\n", rc);
                        GOTO(out, rc);
                }

                ptlrpc_req_finished(request);

                EXIT;
        out:
                obd_ioctl_freedata(buf, len);
                return rc;
        }
        case LL_IOC_LOV_SETSTRIPE: {
                struct lov_user_md_v3 lumv3;
                struct lov_user_md_v1 *lumv1 = (struct lov_user_md_v1 *)&lumv3;
                struct lov_user_md_v1 *lumv1p = (struct lov_user_md_v1 *)arg;
                struct lov_user_md_v3 *lumv3p = (struct lov_user_md_v3 *)arg;

                int rc = 0;
                int set_default = 0;

                LASSERT(sizeof(lumv3) == sizeof(*lumv3p));
                LASSERT(sizeof(lumv3.lmm_objects[0]) ==
                        sizeof(lumv3p->lmm_objects[0]));

                /* first try with v1 which is smaller than v3 */
                if (copy_from_user(lumv1, lumv1p, sizeof(*lumv1)))
                        RETURN(-EFAULT);

                if (lumv1->lmm_magic == LOV_USER_MAGIC_V3) {
                        if (copy_from_user(&lumv3, lumv3p, sizeof(lumv3)))
                                RETURN(-EFAULT);
                }

                if (inode->i_sb->s_root == file->f_dentry)
                        set_default = 1;

                /* in v1 and v3 cases lumv1 points to data */
                rc = ll_dir_setstripe(inode, lumv1, set_default);

                return rc;
        }
        case LL_IOC_OBD_STATFS:
                RETURN(ll_obd_statfs(inode, (void *)arg));
        case LL_IOC_LOV_GETSTRIPE:
        case LL_IOC_MDC_GETINFO:
        case IOC_MDC_GETFILEINFO:
        case IOC_MDC_GETFILESTRIPE: {
                struct ptlrpc_request *request = NULL;
                struct mds_body *body;
                struct lov_user_md *lump;
                struct lov_mds_md *lmm = NULL;
                char *filename = NULL;
                int rc, lmmsize;

                if (cmd == IOC_MDC_GETFILEINFO ||
                    cmd == IOC_MDC_GETFILESTRIPE) {
                        filename = getname((const char *)arg);
                        if (IS_ERR(filename))
                                RETURN(PTR_ERR(filename));

                        rc = ll_lov_getstripe_ea_info(inode, filename, &lmm,
                                                      &lmmsize, &request);
                } else {
                        rc = ll_dir_getstripe(inode, &lmm, &lmmsize, &request);
                }

                if (request) {
                        body = lustre_msg_buf(request->rq_repmsg, REPLY_REC_OFF,
                                              sizeof(*body));
                        LASSERT(body != NULL); /* checked by mdc_getattr_name */
                        /* swabbed by mdc_getattr_name */
                        LASSERT(lustre_rep_swabbed(request, REPLY_REC_OFF));
                } else {
                        GOTO(out_req, rc);
                }

                if (rc < 0) {
                        if (rc == -ENODATA && (cmd == IOC_MDC_GETFILEINFO ||
                                               cmd == LL_IOC_MDC_GETINFO))
                                GOTO(skip_lmm, rc = 0);
                        else
                                GOTO(out_req, rc);
                }

                if (cmd == IOC_MDC_GETFILESTRIPE ||
                    cmd == LL_IOC_LOV_GETSTRIPE) {
                        lump = (struct lov_user_md *)arg;
                } else {
                        struct lov_user_mds_data *lmdp;
                        lmdp = (struct lov_user_mds_data *)arg;
                        lump = &lmdp->lmd_lmm;
                }
                if (copy_to_user(lump, lmm, lmmsize) != 0) {
                        if (copy_to_user(lump, lmm, sizeof(*lump)) != 0)
                                GOTO(out_lmm, rc = -EFAULT);
                        rc = -EOVERFLOW;
                }
        skip_lmm:
                if (cmd == IOC_MDC_GETFILEINFO || cmd == LL_IOC_MDC_GETINFO) {
                        struct lov_user_mds_data *lmdp;
                        lstat_t st = { 0 };

                        st.st_dev     = inode->i_sb->s_dev;
                        st.st_mode    = body->mode;
                        st.st_nlink   = body->nlink;
                        st.st_uid     = body->uid;
                        st.st_gid     = body->gid;
                        st.st_rdev    = body->rdev;
                        st.st_size    = body->size;
                        st.st_blksize = CFS_PAGE_SIZE;
                        st.st_blocks  = body->blocks;
                        st.st_atime   = body->atime;
                        st.st_mtime   = body->mtime;
                        st.st_ctime   = body->ctime;
                        st.st_ino     = body->ino;

                        lmdp = (struct lov_user_mds_data *)arg;
                        if (copy_to_user(&lmdp->lmd_st, &st, sizeof(st)))
                                GOTO(out_lmm, rc = -EFAULT);
                }

                EXIT;
        out_lmm:
                if (lmm && lmm->lmm_magic == LOV_MAGIC_JOIN)
                        OBD_FREE(lmm, lmmsize);
        out_req:
                ptlrpc_req_finished(request);
                if (filename)
                        putname(filename);
                return rc;
        }
        case IOC_LOV_GETINFO: {
                struct lov_user_mds_data *lumd;
                struct lov_stripe_md *lsm;
                struct lov_user_md *lum;
                struct lov_mds_md *lmm;
                int lmmsize;
                lstat_t st;
                int rc;

                lumd = (struct lov_user_mds_data *)arg;
                lum = &lumd->lmd_lmm;

                rc = ll_get_max_mdsize(sbi, &lmmsize);
                if (rc)
                        RETURN(rc);

                OBD_ALLOC(lmm, lmmsize);
                if (copy_from_user(lmm, lum, lmmsize))
                        GOTO(free_lmm, rc = -EFAULT);

                if (LOV_USER_MAGIC != cpu_to_le32(LOV_USER_MAGIC)) {
                        rc = lustre_swab_lov_user_md(
                                                (struct lov_user_md_v1 *)lmm);
                        if (rc) 
                                GOTO(free_lmm, rc);
                        rc = lustre_swab_lov_user_md_objects(
                                                (struct lov_user_md*)lmm);
                        if (rc) 
                                GOTO(free_lmm, rc);
                }

                rc = obd_unpackmd(sbi->ll_osc_exp, &lsm, lmm, lmmsize);
                if (rc < 0)
                        GOTO(free_lmm, rc = -ENOMEM);

                rc = obd_checkmd(sbi->ll_osc_exp, sbi->ll_mdc_exp, lsm);
                if (rc)
                        GOTO(free_lsm, rc);

                /* Perform glimpse_size operation. */
                memset(&st, 0, sizeof(st));

                rc = ll_glimpse_ioctl(sbi, lsm, &st);
                if (rc)
                        GOTO(free_lsm, rc);

                if (copy_to_user(&lumd->lmd_st, &st, sizeof(st)))
                        GOTO(free_lsm, rc = -EFAULT);

                EXIT;
        free_lsm:
                obd_free_memmd(sbi->ll_osc_exp, &lsm);
        free_lmm:
                OBD_FREE(lmm, lmmsize);
                return rc;
        }
        case OBD_IOC_LLOG_CATINFO: {
                struct ptlrpc_request *req = NULL;
                char *buf = NULL;
                int rc, len = 0;
                char *bufs[3] = { NULL }, *str;
                int lens[3] = { sizeof(struct ptlrpc_body) };
                int size[2] = { sizeof(struct ptlrpc_body) };

                rc = obd_ioctl_getdata(&buf, &len, (void *)arg);
                if (rc)
                        RETURN(rc);
                data = (void *)buf;

                if (!data->ioc_inlbuf1) {
                        obd_ioctl_freedata(buf, len);
                        RETURN(-EINVAL);
                }

                lens[REQ_REC_OFF] = data->ioc_inllen1;
                bufs[REQ_REC_OFF] = data->ioc_inlbuf1;
                if (data->ioc_inllen2) {
                        lens[REQ_REC_OFF + 1] = data->ioc_inllen2;
                        bufs[REQ_REC_OFF + 1] = data->ioc_inlbuf2;
                } else {
                        lens[REQ_REC_OFF + 1] = 0;
                        bufs[REQ_REC_OFF + 1] = NULL;
                }

                req = ptlrpc_prep_req(sbi2mdc(sbi)->cl_import,
                                      LUSTRE_LOG_VERSION, LLOG_CATINFO, 3, lens,
                                      bufs);
                if (!req)
                        GOTO(out_catinfo, rc = -ENOMEM);

                size[REPLY_REC_OFF] = data->ioc_plen1;
                ptlrpc_req_set_repsize(req, 2, size);

                rc = ptlrpc_queue_wait(req);
                str = lustre_msg_string(req->rq_repmsg, REPLY_REC_OFF,
                                        data->ioc_plen1);
                if (!rc)
                        if (copy_to_user(data->ioc_pbuf1, str,data->ioc_plen1))
                                rc = -EFAULT;
                ptlrpc_req_finished(req);
        out_catinfo:
                obd_ioctl_freedata(buf, len);
                RETURN(rc);
        }
        case OBD_IOC_QUOTACHECK: {
                struct obd_quotactl *oqctl;
                int rc, error = 0;

                if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                        RETURN(-EPERM);

                OBD_ALLOC_PTR(oqctl);
                if (!oqctl)
                        RETURN(-ENOMEM);
                oqctl->qc_type = arg;
                rc = obd_quotacheck(sbi->ll_mdc_exp, oqctl);
                if (rc < 0) {
                        CDEBUG(D_INFO, "mdc_quotacheck failed: rc %d\n", rc);
                        error = rc;
                }

                rc = obd_quotacheck(sbi->ll_osc_exp, oqctl);
                if (rc < 0)
                        CDEBUG(D_INFO, "osc_quotacheck failed: rc %d\n", rc);

                OBD_FREE_PTR(oqctl);
                return error ?: rc;
        }
        case OBD_IOC_POLL_QUOTACHECK: {
                struct if_quotacheck *check;
                int rc;

                if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                        RETURN(-EPERM);

                OBD_ALLOC_PTR(check);
                if (!check)
                        RETURN(-ENOMEM);

                rc = obd_iocontrol(cmd, sbi->ll_mdc_exp, 0, (void *)check,
                                   NULL);
                if (rc) {
                        CDEBUG(D_QUOTA, "mdc ioctl %d failed: %d\n", cmd, rc);
                        if (copy_to_user((void *)arg, check, sizeof(*check)))
                                CDEBUG(D_QUOTA, "copy_to_user failed\n");
                        GOTO(out_poll, rc);
                }

                rc = obd_iocontrol(cmd, sbi->ll_osc_exp, 0, (void *)check,
                                   NULL);
                if (rc) {
                        CDEBUG(D_QUOTA, "osc ioctl %d failed: %d\n", cmd, rc);
                        if (copy_to_user((void *)arg, check, sizeof(*check)))
                                CDEBUG(D_QUOTA, "copy_to_user failed\n");
                        GOTO(out_poll, rc);
                }
        out_poll:
                OBD_FREE_PTR(check);
                RETURN(rc);
        }
        case OBD_IOC_QUOTACTL: {
                struct if_quotactl *qctl;
                struct obd_quotactl *oqctl;

                int cmd, type, id, rc = 0;

                OBD_ALLOC_PTR(qctl);
                if (!qctl)
                        RETURN(-ENOMEM);

                OBD_ALLOC_PTR(oqctl);
                if (!oqctl) {
                        OBD_FREE_PTR(qctl);
                        RETURN(-ENOMEM);
                }
                if (copy_from_user(qctl, (void *)arg, sizeof(*qctl)))
                        GOTO(out_quotactl, rc = -EFAULT);

                cmd = qctl->qc_cmd;
                type = qctl->qc_type;
                id = qctl->qc_id;
                switch (cmd) {
                case LUSTRE_Q_INVALIDATE:
                case LUSTRE_Q_FINVALIDATE:
                case Q_QUOTAON:
                case Q_QUOTAOFF:
                case Q_SETQUOTA:
                case Q_SETINFO:
                        if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                                GOTO(out_quotactl, rc = -EPERM);
                        break;
                case Q_GETQUOTA:
                        if (((type == USRQUOTA && cfs_curproc_euid() != id) ||
                             (type == GRPQUOTA && !in_egroup_p(id))) &&
                            !cfs_capable(CFS_CAP_SYS_ADMIN))
                                GOTO(out_quotactl, rc = -EPERM);

                        /* XXX: dqb_valid is borrowed as a flag to mark that
                         *      only mds quota is wanted */
                        if (qctl->qc_dqblk.dqb_valid) {
                                qctl->obd_uuid = sbi->ll_mdc_exp->exp_obd->
                                                        u.cli.cl_target_uuid;
                                qctl->qc_dqblk.dqb_valid = 0;
                        }

                        break;
                case Q_GETINFO:
                        break;
                default:
                        CERROR("unsupported quotactl op: %#x\n", cmd);
                        GOTO(out_quotactl, -ENOTTY);
                }

                QCTL_COPY(oqctl, qctl);

                if (qctl->obd_uuid.uuid[0]) {
                        struct obd_device *obd;
                        struct obd_uuid *uuid = &qctl->obd_uuid;

                        obd = class_find_client_notype(uuid,
                                         &sbi->ll_osc_exp->exp_obd->obd_uuid);
                        if (!obd)
                                GOTO(out_quotactl, rc = -ENOENT);

                        if (cmd == Q_GETINFO)
                                oqctl->qc_cmd = Q_GETOINFO;
                        else if (cmd == Q_GETQUOTA)
                                oqctl->qc_cmd = Q_GETOQUOTA;
                        else
                                GOTO(out_quotactl, rc = -EINVAL);

                        if (sbi->ll_mdc_exp->exp_obd == obd) {
                                rc = obd_quotactl(sbi->ll_mdc_exp, oqctl);
                        } else {
                                int i;
                                struct obd_export *exp;
                                struct lov_obd *lov = &sbi->ll_osc_exp->
                                                            exp_obd->u.lov;

                                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                                        if (!lov->lov_tgts[i] ||
                                            !lov->lov_tgts[i]->ltd_active)
                                                continue;
                                        exp = lov->lov_tgts[i]->ltd_exp;
                                        if (exp->exp_obd == obd) {
                                                rc = obd_quotactl(exp, oqctl);
                                                break;
                                        }
                                }
                        }

                        oqctl->qc_cmd = cmd;
                        QCTL_COPY(qctl, oqctl);

                        if (copy_to_user((void *)arg, qctl, sizeof(*qctl)))
                                rc = -EFAULT;

                        GOTO(out_quotactl, rc);
                }

                rc = obd_quotactl(sbi->ll_mdc_exp, oqctl);
                if (rc && rc != -EBUSY && cmd == Q_QUOTAON) {
                        oqctl->qc_cmd = Q_QUOTAOFF;
                        obd_quotactl(sbi->ll_mdc_exp, oqctl);
                }

                /* If QIF_SPACE is not set, client should collect the
                 * space usage from OSSs by itself */
                if (cmd == Q_GETQUOTA &&
                    !(oqctl->qc_dqblk.dqb_valid & QIF_SPACE) &&
                    !oqctl->qc_dqblk.dqb_curspace) {
                        struct obd_quotactl *oqctl_tmp;

                        OBD_ALLOC_PTR(oqctl_tmp);
                        if (oqctl_tmp == NULL)
                                GOTO(out_quotactl, rc = -ENOMEM);

                        oqctl_tmp->qc_cmd = Q_GETOQUOTA;
                        oqctl_tmp->qc_id = oqctl->qc_id;
                        oqctl_tmp->qc_type = oqctl->qc_type;

                        /* collect space usage from OSTs */
                        oqctl_tmp->qc_dqblk.dqb_curspace = 0;
                        rc = obd_quotactl(sbi->ll_osc_exp, oqctl_tmp);
                        if (!rc || rc == -EREMOTEIO) {
                                oqctl->qc_dqblk.dqb_curspace =
                                        oqctl_tmp->qc_dqblk.dqb_curspace;
                                oqctl->qc_dqblk.dqb_valid |= QIF_SPACE;
                        }

                        /* collect space & inode usage from MDTs */
                        oqctl_tmp->qc_dqblk.dqb_curspace = 0;
                        oqctl_tmp->qc_dqblk.dqb_curinodes = 0;
                        rc = obd_quotactl(sbi->ll_mdc_exp, oqctl_tmp);
                        if (!rc || rc == -EREMOTEIO) {
                                oqctl->qc_dqblk.dqb_curspace +=
                                        oqctl_tmp->qc_dqblk.dqb_curspace;
                                oqctl->qc_dqblk.dqb_curinodes =
                                        oqctl_tmp->qc_dqblk.dqb_curinodes;
                                oqctl->qc_dqblk.dqb_valid |= QIF_INODES;
                        } else {
                                oqctl->qc_dqblk.dqb_valid &= ~QIF_SPACE;
                        }

                        OBD_FREE_PTR(oqctl_tmp);
                }

                QCTL_COPY(qctl, oqctl);

                if (copy_to_user((void *)arg, qctl, sizeof(*qctl)))
                        rc = -EFAULT;
        out_quotactl:
                OBD_FREE_PTR(qctl);
                OBD_FREE_PTR(oqctl);
                RETURN(rc);
        }
        case OBD_IOC_GETNAME_OLD:
        case OBD_IOC_GETNAME: {
                struct obd_device *obd = class_exp2obd(sbi->ll_osc_exp);
                if (!obd)
                        RETURN(-EFAULT);
                if (copy_to_user((void *)arg, obd->obd_name,
                                strlen(obd->obd_name) + 1))
                        RETURN (-EFAULT);
                RETURN(0);
        }
        case LL_IOC_PATH2FID: {
                if (copy_to_user((void *)arg, ll_inode_lu_fid(inode),
                                 sizeof(struct lu_fid)))
                        RETURN(-EFAULT);

                RETURN(0);
        }
        case LL_IOC_GET_CONNECT_FLAGS: {
                if (copy_to_user((void *)arg,
                                 &sbi->ll_mdc_exp->exp_connect_flags,
                                 sizeof(__u64)))
                        RETURN(-EFAULT);
                RETURN(0);
        }
        default:
                RETURN(obd_iocontrol(cmd, sbi->ll_osc_exp,0,NULL,(void *)arg));
        }
}

static loff_t ll_dir_seek(struct file *file, loff_t offset, int origin)
{
        struct inode *inode = file->f_mapping->host;
        struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int api32 = ll_need_32bit_api(sbi);
        loff_t ret = -EINVAL;
        ENTRY;

        if (!(sbi->ll_mdc_exp->exp_connect_flags & OBD_CONNECT_FID))
                return default_llseek(file, offset, origin);

        mutex_lock(&inode->i_mutex);
        switch (origin) {
                case SEEK_SET:
                        break;
                case SEEK_CUR:
                        offset += file->f_pos;
                        break;
                case SEEK_END:
                        if (offset > 0)
                                GOTO(out, ret);
                        if (api32)
                                offset += LL_DIR_END_OFF_32BIT;
                        else
                                offset += LL_DIR_END_OFF;
                        break;
                default:
                        GOTO(out, ret);
        }

        if (offset >= 0 &&
            ((api32 && offset <= LL_DIR_END_OFF_32BIT) ||
             (!api32 && offset <= LL_DIR_END_OFF))) {
                if (offset != file->f_pos) {
                        if ((api32 && offset == LL_DIR_END_OFF_32BIT) ||
                            (!api32 && offset == LL_DIR_END_OFF))
                                fd->fd_dir.lfd_pos = MDS_DIR_END_OFF;
                        else if (api32 && sbi->ll_flags & LL_SBI_64BIT_HASH)
                                fd->fd_dir.lfd_pos = offset << 32;
                        else
                                fd->fd_dir.lfd_pos = offset;
                        file->f_pos = offset;
                        file->f_version = 0;
                }
                ret = offset;
        }
        GOTO(out, ret);

out:
        mutex_unlock(&inode->i_mutex);
        return ret;
}

struct file_operations ll_dir_operations = {
        .open     = ll_file_open,
        .llseek   = ll_dir_seek,
        .release  = ll_file_release,
        .read     = generic_read_dir,
        .readdir  = ll_readdir,
        .ioctl    = ll_dir_ioctl,
        .fsync    = ll_fsync
};
