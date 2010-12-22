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

#include <linux/page-flags.h>

#include <lustre_lite.h>
#include "llite_internal.h"
#include <linux/lustre_compat25.h>

#ifndef list_for_each_prev_safe
#define list_for_each_prev_safe(pos, n, head) \
        for (pos = (head)->prev, n = pos->prev; pos != (head); \
                pos = n, n = pos->prev )
#endif

cfs_mem_cache_t *ll_async_page_slab = NULL;
size_t ll_async_page_slab_size = 0;

/* SYNCHRONOUS I/O to object storage for an inode */
static int ll_brw(int cmd, struct inode *inode, struct obdo *oa,
                  struct page *page, int flags)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obd_info oinfo = { { { 0 } } };
        struct brw_page pg;
        int rc;
        ENTRY;

        pg.pg = page;
        pg.off = ((obd_off)page->index) << CFS_PAGE_SHIFT;

        if ((cmd & OBD_BRW_WRITE) && (pg.off+CFS_PAGE_SIZE>i_size_read(inode)))
                pg.count = i_size_read(inode) % CFS_PAGE_SIZE;
        else
                pg.count = CFS_PAGE_SIZE;

        LL_CDEBUG_PAGE(D_PAGE, page, "%s %d bytes ino %lu at "LPU64"/"LPX64"\n",
                       cmd & OBD_BRW_WRITE ? "write" : "read", pg.count,
                       inode->i_ino, pg.off, pg.off);
        if (pg.count == 0) {
                CERROR("ZERO COUNT: ino %lu: size %p:%Lu(%p:%Lu) idx %lu off "
                       LPU64"\n", inode->i_ino, inode, i_size_read(inode),
                       page->mapping->host, i_size_read(page->mapping->host),
                       page->index, pg.off);
        }

        pg.flag = flags;

        if (cmd & OBD_BRW_WRITE)
                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_BRW_WRITE,
                                   pg.count);
        else
                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_BRW_READ,
                           pg.count);
        oinfo.oi_oa = oa;
        oinfo.oi_md = lsm;
        rc = obd_brw(cmd, ll_i2obdexp(inode), &oinfo, 1, &pg, NULL);
        if (rc == 0)
                obdo_to_inode(inode, oa, OBD_MD_FLBLOCKS);
        else if (rc != -EIO)
                CERROR("error from obd_brw: rc = %d\n", rc);
        RETURN(rc);
}

int ll_file_punch(struct inode * inode, loff_t new_size, int srvlock)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_info oinfo = { { { 0 } } };
        struct obdo oa = { 0 };
        obd_valid valid;
        int rc;

        ENTRY;
        CDEBUG(D_INFO, "calling punch for "LPX64" (new size %Lu=%#Lx)\n",
               lli->lli_smd->lsm_object_id, new_size, new_size);

        oinfo.oi_md = lli->lli_smd;
        oinfo.oi_policy.l_extent.start = new_size;
        oinfo.oi_policy.l_extent.end = OBD_OBJECT_EOF;
        oinfo.oi_oa = &oa;
        oa.o_id = lli->lli_smd->lsm_object_id;
        oa.o_gr = lli->lli_smd->lsm_object_gr;
        oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;

        valid = OBD_MD_FLTYPE | OBD_MD_FLMODE |OBD_MD_FLFID |
                OBD_MD_FLATIME | OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLGENER |
                OBD_MD_FLBLOCKS;
        if (srvlock) {
                /* set OBD_MD_FLFLAGS in o_valid, only if we
                 * set OBD_FL_TRUNCLOCK, otherwise ost_punch
                 * and filter_setattr get confused, see the comment
                 * in ost_punch */
                oa.o_flags = OBD_FL_TRUNCLOCK;
                oa.o_valid |= OBD_MD_FLFLAGS;

                /* lockless truncate
                 *
                 * 1. do not use inode's timestamps because concurrent
                 * stat might fill the inode with out-of-date times,
                 * send current instead
                 *
                 * 2.do no update lsm, as long as stat (via
                 * ll_glimpse_size) will bring attributes from osts
                 * anyway */
                oa.o_mtime = oa.o_ctime = LTIME_S(CURRENT_TIME);
                oa.o_valid |= OBD_MD_FLMTIME | OBD_MD_FLCTIME;
        } else {
                struct ost_lvb *xtimes;
                /* truncate under locks
                 *
                 * 1. update inode's mtime and ctime as long as
                 * concurrent stat (via ll_glimpse_size) might bring
                 * out-of-date ones
                 *
                 * 2. update lsm so that next stat (via
                 * ll_glimpse_size) could get correct values in lsm */
                OBD_ALLOC_PTR(xtimes);
                if (NULL == xtimes)
                        RETURN(-ENOMEM);

                lov_stripe_lock(lli->lli_smd);
                LTIME_S(inode->i_mtime) = LTIME_S(CURRENT_TIME);
                LTIME_S(inode->i_ctime) = LTIME_S(CURRENT_TIME);
                xtimes->lvb_mtime = LTIME_S(inode->i_mtime);
                xtimes->lvb_ctime = LTIME_S(inode->i_ctime);
                obd_update_lvb(ll_i2obdexp(inode), lli->lli_smd, xtimes,
                               OBD_MD_FLMTIME | OBD_MD_FLCTIME);
                lov_stripe_unlock(lli->lli_smd);
                OBD_FREE_PTR(xtimes);

                valid |= OBD_MD_FLMTIME | OBD_MD_FLCTIME;
        }
        obdo_from_inode(&oa, inode, valid);

        rc = obd_punch_rqset(ll_i2obdexp(inode), &oinfo, NULL);
        if (rc) {
                CERROR("obd_truncate fails (%d) ino %lu\n", rc, inode->i_ino);
                RETURN(rc);
        }
        obdo_to_inode(inode, &oa, OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                      OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME);
        RETURN(0);
}
/* this isn't where truncate starts.   roughly:
 * sys_truncate->ll_setattr_raw->vmtruncate->ll_truncate. setattr_raw grabs
 * DLM lock on [size, EOF], i_mutex, ->lli_size_sem, and WRITE_I_ALLOC_SEM to
 * avoid races.
 *
 * must be called under ->lli_size_sem */
void ll_truncate(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        int srvlock = test_bit(LLI_F_SRVLOCK, &lli->lli_flags);
        loff_t new_size;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p) to %Lu=%#Lx\n",
               inode->i_ino, inode->i_generation, inode, i_size_read(inode),
               i_size_read(inode));

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_TRUNC, 1);
        if (lli->lli_size_sem_owner != current) {
                EXIT;
                return;
        }

        if (!lli->lli_smd) {
                CDEBUG(D_INODE, "truncate on inode %lu with no objects\n",
                       inode->i_ino);
                GOTO(out_unlock, 0);
        }

        LASSERT(SEM_COUNT(&lli->lli_size_sem) <= 0);

        if (!srvlock) {
                struct ost_lvb lvb;
                int rc;

                /* XXX I'm pretty sure this is a hack to paper over a more
                 * fundamental race condition. */
                lov_stripe_lock(lli->lli_smd);
                inode_init_lvb(inode, &lvb);
                rc = obd_merge_lvb(ll_i2obdexp(inode), lli->lli_smd, &lvb, 0);
                inode->i_blocks = lvb.lvb_blocks;
                if (lvb.lvb_size == i_size_read(inode) && rc == 0) {
                        CDEBUG(D_VFSTRACE, "skipping punch for obj "LPX64
                               ", %Lu=%#Lx\n",
                               lli->lli_smd->lsm_object_id, i_size_read(inode),
                               i_size_read(inode));
                        lov_stripe_unlock(lli->lli_smd);
                        GOTO(out_unlock, 0);
                }

                obd_adjust_kms(ll_i2obdexp(inode), lli->lli_smd,
                               i_size_read(inode), 1);
                lov_stripe_unlock(lli->lli_smd);
        }

        if (unlikely((ll_i2sbi(inode)->ll_flags & LL_SBI_LLITE_CHECKSUM) &&
                     (i_size_read(inode) & ~CFS_PAGE_MASK))) {
                /* If the truncate leaves a partial page, update its checksum */
                struct page *page = find_get_page(inode->i_mapping,
                                                  i_size_read(inode) >>
                                                  CFS_PAGE_SHIFT);
                if (page != NULL) {
                        struct ll_async_page *llap = llap_cast_private(page);
                        if (llap != NULL) {
                                char *kaddr = kmap_atomic(page, KM_USER0);
                                llap->llap_checksum =
                                        init_checksum(OSC_DEFAULT_CKSUM);
                                llap->llap_checksum =
                                        compute_checksum(llap->llap_checksum,
                                                         kaddr, CFS_PAGE_SIZE,
                                                         OSC_DEFAULT_CKSUM);
                                kunmap_atomic(kaddr, KM_USER0);
                        }
                        page_cache_release(page);
                }
        }

        new_size = i_size_read(inode);
        ll_inode_size_unlock(inode, 0);
        if (!srvlock)
                ll_file_punch(inode, new_size, 0);
        else
                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_LOCKLESS_TRUNC, 1);

        EXIT;
        return;

 out_unlock:
        ll_inode_size_unlock(inode, 0);
} /* ll_truncate */

int ll_prepare_write(struct file *file, struct page *page, unsigned from,
                     unsigned to)
{
        struct inode *inode = page->mapping->host;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        obd_off offset = ((obd_off)page->index) << CFS_PAGE_SHIFT;
        struct obd_info oinfo = { { { 0 } } };
        struct brw_page pga;
        struct obdo oa = { 0 };
        struct ost_lvb lvb;
        int rc = 0;
        ENTRY;

        LASSERT(PageLocked(page));
        (void)llap_cast_private(page); /* assertion */

        /* Check to see if we should return -EIO right away */
        pga.pg = page;
        pga.off = offset;
        pga.count = CFS_PAGE_SIZE;
        pga.flag = 0;

        oa.o_mode = inode->i_mode;
        oa.o_id = lsm->lsm_object_id;
        oa.o_gr = lsm->lsm_object_gr;
        oa.o_valid = OBD_MD_FLID   | OBD_MD_FLMODE |
                     OBD_MD_FLTYPE | OBD_MD_FLGROUP;
        obdo_from_inode(&oa, inode, OBD_MD_FLFID | OBD_MD_FLGENER);

        oinfo.oi_oa = &oa;
        oinfo.oi_md = lsm;
        rc = obd_brw(OBD_BRW_CHECK, ll_i2obdexp(inode), &oinfo, 1, &pga, NULL);
        if (rc)
                RETURN(rc);

        if (PageUptodate(page)) {
                LL_CDEBUG_PAGE(D_PAGE, page, "uptodate\n");
                RETURN(0);
        }

        /* We're completely overwriting an existing page, so _don't_ set it up
         * to date until commit_write */
        if (from == 0 && to == CFS_PAGE_SIZE) {
                LL_CDEBUG_PAGE(D_PAGE, page, "full page write\n");
                POISON_PAGE(page, 0x11);
                RETURN(0);
        }

        /* If are writing to a new page, no need to read old data.  The extent
         * locking will have updated the KMS, and for our purposes here we can
         * treat it like i_size. */
        lov_stripe_lock(lsm);
        inode_init_lvb(inode, &lvb);
        obd_merge_lvb(ll_i2obdexp(inode), lsm, &lvb, 1);
        lov_stripe_unlock(lsm);
        if (lvb.lvb_size <= offset) {
                char *kaddr = kmap_atomic(page, KM_USER0);
                LL_CDEBUG_PAGE(D_PAGE, page, "kms "LPU64" <= offset "LPU64"\n",
                               lvb.lvb_size, offset);
                memset(kaddr, 0, CFS_PAGE_SIZE);
                kunmap_atomic(kaddr, KM_USER0);
                GOTO(prepare_done, rc = 0);
        }

        /* XXX could be an async ocp read.. read-ahead? */
        rc = ll_brw(OBD_BRW_READ, inode, &oa, page, 0);
        if (rc == 0) {
                /* bug 1598: don't clobber blksize */
                oa.o_valid &= ~(OBD_MD_FLSIZE | OBD_MD_FLBLKSZ);
                obdo_refresh_inode(inode, &oa, oa.o_valid);
        }

        EXIT;
 prepare_done:
        if (rc == 0)
                SetPageUptodate(page);

        return rc;
}

/**
 * make page ready for ASYNC write
 * \param data - pointer to llap cookie
 * \param cmd - is OBD_BRW_* macroses
 *
 * \retval 0 is page successfully prepared to send
 * \retval -EAGAIN is page not need to send
 */
static int ll_ap_make_ready(void *data, int cmd)
{
        struct ll_async_page *llap;
        struct page *page;
        ENTRY;

        llap = LLAP_FROM_COOKIE(data);
        page = llap->llap_page;

        /* we're trying to write, but the page is locked.. come back later */
        if (TryLockPage(page))
                RETURN(-EAGAIN);

        LASSERTF(!(cmd & OBD_BRW_READ) || !PageWriteback(page),
                "cmd %x page %p ino %lu index %lu fl %lx\n", cmd, page,
                 page->mapping->host->i_ino, page->index, (long)page->flags);

        /* if we left PageDirty we might get another writepage call
         * in the future.  list walkers are bright enough
         * to check page dirty so we can leave it on whatever list
         * its on.  XXX also, we're called with the cli list so if
         * we got the page cache list we'd create a lock inversion
         * with the removepage path which gets the page lock then the
         * cli lock */
        if(!clear_page_dirty_for_io(page)) {
                unlock_page(page);
                RETURN(-EAGAIN);
        }

        /* This actually clears the dirty bit in the radix tree.*/
        set_page_writeback(page);

        LL_CDEBUG_PAGE(D_PAGE, page, "made ready\n");
        page_cache_get(page);

        RETURN(0);
}

/* We have two reasons for giving llite the opportunity to change the
 * write length of a given queued page as it builds the RPC containing
 * the page:
 *
 * 1) Further extending writes may have landed in the page cache
 *    since a partial write first queued this page requiring us
 *    to write more from the page cache.  (No further races are possible,
 *    since by the time this is called, the page is locked.)
 * 2) We might have raced with truncate and want to avoid performing
 *    write RPCs that are just going to be thrown away by the
 *    truncate's punch on the storage targets.
 *
 * The kms serves these purposes as it is set at both truncate and extending
 * writes.
 */
static int ll_ap_refresh_count(void *data, int cmd)
{
        struct ll_inode_info *lli;
        struct ll_async_page *llap;
        struct lov_stripe_md *lsm;
        struct page *page;
        struct inode *inode;
        struct ost_lvb lvb;
        __u64 kms;
        ENTRY;

        /* readpage queues with _COUNT_STABLE, shouldn't get here. */
        LASSERT(cmd != OBD_BRW_READ);

        llap = LLAP_FROM_COOKIE(data);
        page = llap->llap_page;
        inode = page->mapping->host;
        lli = ll_i2info(inode);
        lsm = lli->lli_smd;

        lov_stripe_lock(lsm);
        inode_init_lvb(inode, &lvb);
        obd_merge_lvb(ll_i2obdexp(inode), lsm, &lvb, 1);
        kms = lvb.lvb_size;
        lov_stripe_unlock(lsm);

        /* catch race with truncate */
        if (((__u64)page->index << CFS_PAGE_SHIFT) >= kms)
                return 0;

        /* catch sub-page write at end of file */
        if (((__u64)page->index << CFS_PAGE_SHIFT) + CFS_PAGE_SIZE > kms)
                return kms % CFS_PAGE_SIZE;

        return CFS_PAGE_SIZE;
}

void ll_inode_fill_obdo(struct inode *inode, int cmd, struct obdo *oa)
{
        struct lov_stripe_md *lsm;
        obd_flag valid_flags;

        lsm = ll_i2info(inode)->lli_smd;

        oa->o_id = lsm->lsm_object_id;
        oa->o_gr = lsm->lsm_object_gr;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
        valid_flags = OBD_MD_FLTYPE | OBD_MD_FLATIME;
        if (cmd & OBD_BRW_WRITE) {
                oa->o_valid |= OBD_MD_FLEPOCH;
                oa->o_easize = ll_i2info(inode)->lli_io_epoch;

                valid_flags |= OBD_MD_FLMTIME | OBD_MD_FLCTIME |
                        OBD_MD_FLUID | OBD_MD_FLGID |
                        OBD_MD_FLFID | OBD_MD_FLGENER;
        }

        obdo_from_inode(oa, inode, valid_flags);
        /* Bug11742 - set the OBD_FL_MMAP flag for memory mapped files */
        if (atomic_read(&(ll_i2info(inode)->lli_mmap_cnt)) != 0) {
                if (!(oa->o_valid & OBD_MD_FLFLAGS)) {
                        oa->o_valid |= OBD_MD_FLFLAGS;
                        oa->o_flags = OBD_FL_MMAP;
                } else {
                        oa->o_flags |= OBD_FL_MMAP;
                }
        }
}

static void ll_ap_fill_obdo(void *data, int cmd, struct obdo *oa)
{
        struct ll_async_page *llap;
        ENTRY;

        llap = LLAP_FROM_COOKIE(data);
        ll_inode_fill_obdo(llap->llap_page->mapping->host, cmd, oa);

        EXIT;
}

static void ll_ap_update_obdo(void *data, int cmd, struct obdo *oa,
                              obd_valid valid)
{
        struct ll_async_page *llap;
        ENTRY;

        llap = LLAP_FROM_COOKIE(data);
        obdo_from_inode(oa, llap->llap_page->mapping->host, valid);

        EXIT;
}

static struct obd_async_page_ops ll_async_page_ops = {
        .ap_make_ready =        ll_ap_make_ready,
        .ap_refresh_count =     ll_ap_refresh_count,
        .ap_fill_obdo =         ll_ap_fill_obdo,
        .ap_update_obdo =       ll_ap_update_obdo,
        .ap_completion =        ll_ap_completion,
};

struct ll_async_page *llap_cast_private(struct page *page)
{
        struct ll_async_page *llap = (struct ll_async_page *)page_private(page);

        LASSERTF(llap == NULL || llap->llap_magic == LLAP_MAGIC,
                 "page %p private %lu gave magic %d which != %d\n",
                 page, page_private(page), llap->llap_magic, LLAP_MAGIC);

        return llap;
}

/* Try to reap @target pages in the specific @cpu's async page list.
 *
 * There is an llap attached onto every page in lustre, linked off @sbi.
 * We add an llap to the list so we don't lose our place during list walking.
 * If llaps in the list are being moved they will only move to the end
 * of the LRU, and we aren't terribly interested in those pages here (we
 * start at the beginning of the list where the least-used llaps are. */
static inline int llap_shrink_cache_internal(struct ll_sb_info *sbi,
        int cpu, int target)
{
        struct ll_async_page *llap, dummy_llap = { .llap_magic = 0xd11ad11a };
        struct ll_pglist_data *pd;
        struct list_head *head;
        int count = 0;

        pd = ll_pglist_cpu_lock(sbi, cpu);
        head = &pd->llpd_list;
        list_add(&dummy_llap.llap_pglist_item, head);
        while (count < target) {
                struct page *page;
                int keep;

                if (unlikely(need_resched())) {
                        list_del(&dummy_llap.llap_pglist_item);
                        ll_pglist_cpu_unlock(sbi, cpu);
                        /* vmscan::shrink_slab() have own schedule() */
                        return count;
                }

                llap = llite_pglist_next_llap(head,
                        &dummy_llap.llap_pglist_item);
                list_del_init(&dummy_llap.llap_pglist_item);
                if (llap == NULL)
                        break;

                page = llap->llap_page;
                LASSERT(page != NULL);

                list_add(&dummy_llap.llap_pglist_item, &llap->llap_pglist_item);

                /* Page needs/undergoing IO */
                if (TryLockPage(page)) {
                        LL_CDEBUG_PAGE(D_PAGE, page, "can't lock\n");
                        continue;
                }

               keep = (llap->llap_write_queued || PageDirty(page) ||
                      PageWriteback(page) || (!PageUptodate(page) &&
                      llap->llap_origin != LLAP_ORIGIN_READAHEAD));

                LL_CDEBUG_PAGE(D_PAGE, page,
                               "%s LRU page: %s%s%s%s%s origin %s\n",
                               keep ? "keep" : "drop",
                               llap->llap_write_queued ? "wq " : "",
                               PageDirty(page) ? "pd " : "",
                               PageUptodate(page) ? "" : "!pu ",
                               PageWriteback(page) ? "wb" : "",
                               llap->llap_defer_uptodate ? "" : "!du",
                               llap_origins[llap->llap_origin]);

                /* If page is dirty or undergoing IO don't discard it */
                if (keep) {
                        unlock_page(page);
                        continue;
                }

                page_cache_get(page);
                ll_pglist_cpu_unlock(sbi, cpu);

                if (page->mapping != NULL) {
                        ll_teardown_mmaps(page->mapping,
                                         (__u64)page->index << CFS_PAGE_SHIFT,
                                         ((__u64)page->index << CFS_PAGE_SHIFT)|
                                          ~CFS_PAGE_MASK);
                        if (!PageDirty(page) && !page_mapped(page)) {
                                ll_ra_accounting(llap, page->mapping);
                                ll_truncate_complete_page(page);
                                ++count;
                        } else {
                                LL_CDEBUG_PAGE(D_PAGE, page,
                                               "Not dropping page because it is"
                                               " %s\n", PageDirty(page) ?
                                               "dirty" : "mapped");
                        }
                }
                unlock_page(page);
                page_cache_release(page);

                ll_pglist_cpu_lock(sbi, cpu);
        }
        list_del(&dummy_llap.llap_pglist_item);
        ll_pglist_cpu_unlock(sbi, cpu);

        CDEBUG(D_CACHE, "shrank %d, expected %d however. \n", count, target);
        return count;
}


/* Try to shrink the page cache for the @sbi filesystem by 1/@shrink_fraction.
 *
 * At first, this code calculates total pages wanted by @shrink_fraction, then
 * it deduces how many pages should be reaped from each cpu in proportion as
 * their own # of page count(llpd_count).
 */
int llap_shrink_cache(struct ll_sb_info *sbi, int nr_to_scan)
{
        unsigned long total, want, percpu_want, count = 0;
        int cpu, nr_cpus;

        total = lcounter_read_positive(&sbi->ll_async_page_count);
        if (total == 0 || nr_to_scan == 0)
                return total;

        want = nr_to_scan;

        /* Since we are freeing pages also, we don't necessarily want to
         * shrink so much.  Limit to 40MB of pages + llaps per call. */
        if (want > 40 << (20 - CFS_PAGE_SHIFT))
                want = 40 << (20 - CFS_PAGE_SHIFT);

        CDEBUG(D_CACHE, "shrinking %lu of %lu pages (asked for %u)\n",
               want, total, nr_to_scan);

        nr_cpus = num_possible_cpus();
        cpu = sbi->ll_async_page_clock_hand;
        /* we at most do one round */
        do {
                int c;

                cpu = (cpu + 1) % nr_cpus;
                c = LL_PGLIST_DATA_CPU(sbi, cpu)->llpd_count;
                if (!cpu_online(cpu))
                        percpu_want = c;
                else
                        percpu_want = want / ((total / (c + 1)) + 1);
                if (percpu_want == 0)
                        continue;

                count += llap_shrink_cache_internal(sbi, cpu, percpu_want);
                if (count >= want)
                        sbi->ll_async_page_clock_hand = cpu;
        } while (cpu != sbi->ll_async_page_clock_hand);

        CDEBUG(D_CACHE, "shrank %lu/%lu and left %lu unscanned\n",
               count, want, total);

        return lcounter_read_positive(&sbi->ll_async_page_count);
}

/* Rebalance the async page queue len for each cpu. We hope that the cpu
 * which do much IO job has a relative longer queue len.
 * This function should be called with preempt disabled.
 */
static inline int llap_async_cache_rebalance(struct ll_sb_info *sbi)
{
        unsigned long sample = 0, *cpu_sample, bias, slice;
        struct ll_pglist_data *pd;
        cpumask_t mask;
        int cpu, surplus;
        int w1 = 7, w2 = 3, base = (w1 + w2); /* weight value */
        atomic_t *pcnt;

        if (!spin_trylock(&sbi->ll_async_page_reblnc_lock)) {
                /* someone else is doing the job */
                return 1;
        }

        pcnt = &LL_PGLIST_DATA(sbi)->llpd_sample_count;
        if (!atomic_read(pcnt)) {
                /* rare case, somebody else has gotten this job done */
                spin_unlock(&sbi->ll_async_page_reblnc_lock);
                return 1;
        }

        sbi->ll_async_page_reblnc_count++;
        cpu_sample = sbi->ll_async_page_sample;
        memset(cpu_sample, 0, num_possible_cpus() * sizeof(unsigned long));
        for_each_online_cpu(cpu) {
                pcnt = &LL_PGLIST_DATA_CPU(sbi, cpu)->llpd_sample_count;
                cpu_sample[cpu] = atomic_read(pcnt);
                atomic_set(pcnt, 0);
                sample += cpu_sample[cpu];
        }

        cpus_clear(mask);
        surplus = sbi->ll_async_page_max;
        slice = surplus / sample + 1;
        sample /= num_online_cpus();
        bias = sample >> 4;
        for_each_online_cpu(cpu) {
                pd = LL_PGLIST_DATA_CPU(sbi, cpu);
                if (labs((long int)sample - cpu_sample[cpu]) > bias) {
                        unsigned long budget = pd->llpd_budget;
                        /* weighted original queue length and expected queue
                         * length to avoid thrashing. */
                        pd->llpd_budget = (budget * w1) / base +
                                        (slice * cpu_sample[cpu]) * w2 / base;
                        cpu_set(cpu, mask);
                }
                surplus -= min_t(int, pd->llpd_budget, surplus);
        }
        surplus /= cpus_weight(mask) ?: 1;
        for_each_cpu_mask(cpu, mask)
                LL_PGLIST_DATA_CPU(sbi, cpu)->llpd_budget += surplus;
        spin_unlock(&sbi->ll_async_page_reblnc_lock);

        /* We need to call llap_shrink_cache_internal() for every cpu to
         * ensure the sbi->ll_async_page_max limit is enforced. */
        for_each_cpu_mask(cpu, mask) {
                pd = LL_PGLIST_DATA_CPU(sbi, cpu);
                llap_shrink_cache_internal(sbi, cpu, max_t(int, pd->llpd_count-
                                           pd->llpd_budget, 0) + 32);
        }

        return 0;
}

static struct ll_async_page *llap_from_page_with_lockh(struct page *page,
                                                       unsigned origin,
                                                       struct lustre_handle *lockh,
                                                       int flags)
{
        struct ll_async_page *llap;
        struct obd_export *exp;
        struct inode *inode = page->mapping->host;
        struct ll_sb_info *sbi;
        struct ll_pglist_data *pd;
        int rc, cpu, target;
        ENTRY;

        if (!inode) {
                static int triggered;

                if (!triggered) {
                        LL_CDEBUG_PAGE(D_ERROR, page, "Bug 10047. Wrong anon "
                                       "page received\n");
                        libcfs_debug_dumpstack(NULL);
                        triggered = 1;
                }
                RETURN(ERR_PTR(-EINVAL));
        }
        sbi = ll_i2sbi(inode);
        LASSERT(ll_async_page_slab);
        LASSERTF(origin < LLAP__ORIGIN_MAX, "%u\n", origin);

        exp = ll_i2obdexp(page->mapping->host);
        if (exp == NULL)
                RETURN(ERR_PTR(-EINVAL));

        llap = llap_cast_private(page);
        if (llap != NULL) {
#if 0 /* disabled since we take lock ref in readahead, see bug 16774/21252 */
                if (origin == LLAP_ORIGIN_READAHEAD && lockh) {
                        /* the page could belong to another lock for which
                         * we don't hold a reference. We need to check that
                         * a reference is taken on a lock covering this page.
                         * For readpage origin, this is fine because
                         * ll_file_readv() took a reference on lock(s) covering
                         * the whole read. However, for readhead, we don't have
                         * this guarantee, so we need to check that the lock
                         * matched in ll_file_readv() also covers this page */
                        __u64 offset = ((loff_t)page->index) << CFS_PAGE_SHIFT;
                        if (!obd_get_lock(exp, ll_i2info(inode)->lli_smd, 
                                          &llap->llap_cookie, OBD_BRW_READ,
                                          offset, offset + CFS_PAGE_SIZE - 1,
                                          lockh, flags))
                                RETURN(ERR_PTR(-ENOLCK));
                }
#endif
                /* move to end of LRU list, except when page is just about to
                 * die */
                if (origin != LLAP_ORIGIN_REMOVEPAGE) {
                        int old_cpu = llap->llap_pglist_cpu;
                        struct ll_pglist_data *old_pd;

                        pd = ll_pglist_double_lock(sbi, old_cpu, &old_pd);
                        pd->llpd_hit++;
                        while (old_cpu != llap->llap_pglist_cpu) {
                                /* rarely case, someone else is touching this
                                 * page too. */
                                ll_pglist_double_unlock(sbi, old_cpu);
                                old_cpu = llap->llap_pglist_cpu;
                                pd=ll_pglist_double_lock(sbi, old_cpu, &old_pd);
                        }

                        list_move_tail(&llap->llap_pglist_item,
                                       &pd->llpd_list);
                        old_pd->llpd_gen++;
                        if (pd->llpd_cpu != old_cpu) {
                                pd->llpd_count++;
                                old_pd->llpd_count--;
                                old_pd->llpd_gen++;
                                llap->llap_pglist_cpu = pd->llpd_cpu;
                                pd->llpd_cross++;
                        }
                        ll_pglist_double_unlock(sbi, old_cpu);
                }
                GOTO(out, llap);
        }

        /* limit the number of lustre-cached pages */
        cpu = cfs_get_cpu();
        pd = LL_PGLIST_DATA(sbi);
        target = pd->llpd_count - pd->llpd_budget;
        if (target > 0) {
                rc = 0;
                atomic_inc(&pd->llpd_sample_count);
                if (atomic_read(&pd->llpd_sample_count) >
                    sbi->ll_async_page_sample_max) {
                        pd->llpd_reblnc_count++;
                        rc = llap_async_cache_rebalance(sbi);
                        if (rc == 0)
                                target = pd->llpd_count - pd->llpd_budget;
                }
                /* if rc equals 1, it means other cpu is doing the rebalance
                 * job, and our budget # would be modified when we read it.
                 * Furthermore, it is much likely being increased because
                 * we have already reached the rebalance threshold. In this
                 * case, we skip to shrink cache here. */
                if ((rc == 0) && target > 0)
                        llap_shrink_cache_internal(sbi, cpu, target + 32);
        }
        cfs_put_cpu();

        OBD_SLAB_ALLOC(llap, ll_async_page_slab, CFS_ALLOC_IO,
                       ll_async_page_slab_size);
        if (llap == NULL)
                RETURN(ERR_PTR(-ENOMEM));
        llap->llap_magic = LLAP_MAGIC;
        llap->llap_cookie = (void *)llap + size_round(sizeof(*llap));

        rc = obd_prep_async_page(exp, ll_i2info(inode)->lli_smd, NULL, page,
                                 (obd_off)page->index << CFS_PAGE_SHIFT,
                                 &ll_async_page_ops, llap, &llap->llap_cookie,
                                 flags, lockh);
        if (rc) {
                OBD_SLAB_FREE(llap, ll_async_page_slab,
                              ll_async_page_slab_size);
                RETURN(ERR_PTR(rc));
        }

        CDEBUG(D_CACHE, "llap %p page %p cookie %p obj off "LPU64"\n", llap,
               page, llap->llap_cookie, (obd_off)page->index << CFS_PAGE_SHIFT);
        /* also zeroing the PRIVBITS low order bitflags */
        __set_page_ll_data(page, llap);
        llap->llap_page = page;

        lcounter_inc(&sbi->ll_async_page_count);
        pd = ll_pglist_lock(sbi);
        list_add_tail(&llap->llap_pglist_item, &pd->llpd_list);
        pd->llpd_count++;
        pd->llpd_gen++;
        pd->llpd_miss++;
        llap->llap_pglist_cpu = pd->llpd_cpu;
        ll_pglist_unlock(sbi);

 out:
        if (unlikely(sbi->ll_flags & LL_SBI_LLITE_CHECKSUM)) {
                __u32 csum;
                char *kaddr = kmap_atomic(page, KM_USER0);
                csum = init_checksum(OSC_DEFAULT_CKSUM);
                csum = compute_checksum(csum, kaddr, CFS_PAGE_SIZE,
                                        OSC_DEFAULT_CKSUM);
                kunmap_atomic(kaddr, KM_USER0);
                if (origin == LLAP_ORIGIN_READAHEAD ||
                    origin == LLAP_ORIGIN_READPAGE) {
                        llap->llap_checksum = 0;
                } else if (origin == LLAP_ORIGIN_COMMIT_WRITE ||
                           llap->llap_checksum == 0) {
                        llap->llap_checksum = csum;
                        CDEBUG(D_PAGE, "page %p cksum %x\n", page, csum);
                } else if (llap->llap_checksum == csum) {
                        /* origin == LLAP_ORIGIN_WRITEPAGE */
                        CDEBUG(D_PAGE, "page %p cksum %x confirmed\n",
                               page, csum);
                } else {
                        /* origin == LLAP_ORIGIN_WRITEPAGE */
                        if (!atomic_read(&(ll_i2info(inode)->lli_mmap_cnt))) {
			        LL_CDEBUG_PAGE(D_ERROR, page,
                                               "old cksum %x != new %x!\n",
                                               llap->llap_checksum, csum);
                        } else {
                                /* mmapped page was modified */
                                CDEBUG(D_PAGE,
                                       "page %p old cksum %x != new %x\n",
                                       page, llap->llap_checksum, csum);
                        }
                        llap->llap_checksum = csum;
                }
        }

        llap->llap_origin = origin;
        RETURN(llap);
}

static inline struct ll_async_page *llap_from_page(struct page *page,
                                                   unsigned origin)
{
        return llap_from_page_with_lockh(page, origin, NULL, 0);
}

static int queue_or_sync_write(struct obd_export *exp, struct inode *inode,
                               struct ll_async_page *llap,
                               unsigned to, obd_flag async_flags)
{
        unsigned long size_index = i_size_read(inode) >> CFS_PAGE_SHIFT;
        struct obd_io_group *oig;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int rc, noquot = llap->llap_ignore_quota ? OBD_BRW_NOQUOTA : 0;
        int brwflags = OBD_BRW_ASYNC;
        ENTRY;

        /* _make_ready only sees llap once we've unlocked the page */
        llap->llap_write_queued = 1;
        rc = obd_queue_async_io(exp, ll_i2info(inode)->lli_smd, NULL,
                                llap->llap_cookie, OBD_BRW_WRITE | noquot,
                                0, 0, brwflags, async_flags);
        if (rc == 0) {
                LL_CDEBUG_PAGE(D_PAGE, llap->llap_page, "write queued\n");
                llap_write_pending(inode, llap);
                GOTO(out, 0);
        }

        llap->llap_write_queued = 0;

        rc = oig_init(&oig);
        if (rc)
                GOTO(out, rc);

        /* make full-page requests if we are not at EOF (bug 4410) */
        if (to != CFS_PAGE_SIZE && llap->llap_page->index < size_index) {
                LL_CDEBUG_PAGE(D_PAGE, llap->llap_page,
                               "sync write before EOF: size_index %lu, to %d\n",
                               size_index, to);
                to = CFS_PAGE_SIZE;
        } else if (to != CFS_PAGE_SIZE && llap->llap_page->index == size_index){
                int size_to = i_size_read(inode) & ~CFS_PAGE_MASK;
                LL_CDEBUG_PAGE(D_PAGE, llap->llap_page,
                               "sync write at EOF: size_index %lu, to %d/%d\n",
                               size_index, to, size_to);
                if (to < size_to)
                        to = size_to;
        }

        /* compare the checksum once before the page leaves llite */
        if (unlikely((sbi->ll_flags & LL_SBI_LLITE_CHECKSUM) &&
                     llap->llap_checksum != 0)) {
                __u32 csum;
                struct page *page = llap->llap_page;
                char *kaddr = kmap_atomic(page, KM_USER0);
                csum = init_checksum(OSC_DEFAULT_CKSUM);
                csum = compute_checksum(csum, kaddr, CFS_PAGE_SIZE,
                                        OSC_DEFAULT_CKSUM);
                kunmap_atomic(kaddr, KM_USER0);
                if (llap->llap_checksum == csum) {
                        CDEBUG(D_PAGE, "page %p cksum %x confirmed\n",
                               page, csum);
                } else {
                        CERROR("page %p old cksum %x != new cksum %x!\n",
                               page, llap->llap_checksum, csum);
                }
        }

        rc = obd_queue_group_io(exp, ll_i2info(inode)->lli_smd, NULL, oig,
                                llap->llap_cookie, OBD_BRW_WRITE | noquot,
                                0, to, 0, ASYNC_READY | ASYNC_URGENT |
                                ASYNC_COUNT_STABLE | ASYNC_GROUP_SYNC);
        if (rc)
                GOTO(free_oig, rc);

        rc = obd_trigger_group_io(exp, ll_i2info(inode)->lli_smd, NULL, oig);
        if (rc)
                GOTO(free_oig, rc);

        rc = oig_wait(oig);

        if (!rc && async_flags & ASYNC_READY) {
                unlock_page(llap->llap_page);
                if (PageWriteback(llap->llap_page))
                        end_page_writeback(llap->llap_page);
        }

        LL_CDEBUG_PAGE(D_PAGE, llap->llap_page, "sync write returned %d\n", rc);

free_oig:
        oig_release(oig);
out:
        RETURN(rc);
}

/* update our write count to account for i_size increases that may have
 * happened since we've queued the page for io. */

/* be careful not to return success without setting the page Uptodate or
 * the next pass through prepare_write will read in stale data from disk. */
int ll_commit_write(struct file *file, struct page *page, unsigned from,
                    unsigned to)
{
        struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
        struct inode *inode = page->mapping->host;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obd_export *exp;
        struct ll_async_page *llap;
        loff_t size;
        struct lustre_handle *lockh = NULL;
        int rc = 0;
        ENTRY;

        SIGNAL_MASK_ASSERT(); /* XXX BUG 1511 */
        LASSERT(inode == file->f_dentry->d_inode);
        LASSERT(PageLocked(page));

        CDEBUG(D_INODE, "inode %p is writing page %p from %d to %d at %lu\n",
               inode, page, from, to, page->index);

        if (fd->fd_flags & LL_FILE_GROUP_LOCKED)
                lockh = &fd->fd_cwlockh;

        llap = llap_from_page_with_lockh(page, LLAP_ORIGIN_COMMIT_WRITE, lockh,
                                         0);
        if (IS_ERR(llap))
                RETURN(PTR_ERR(llap));

        exp = ll_i2obdexp(inode);
        if (exp == NULL)
                RETURN(-EINVAL);

        llap->llap_ignore_quota = cfs_capable(CFS_CAP_SYS_RESOURCE);

        /* queue a write for some time in the future the first time we
         * dirty the page */
        if (!PageDirty(page)) {
                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_DIRTY_MISSES, 1);

                rc = queue_or_sync_write(exp, inode, llap, to, 0);
                if (rc)
                        GOTO(out, rc);
        } else {
                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_DIRTY_HITS, 1);
        }

        /* put the page in the page cache, from now on ll_removepage is
         * responsible for cleaning up the llap.
         * only set page dirty when it's queued to be write out */
        if (llap->llap_write_queued)
                set_page_dirty(page);

out:
        size = (((obd_off)page->index) << CFS_PAGE_SHIFT) + to;
        ll_inode_size_lock(inode, 0);
        if (rc == 0) {
                lov_stripe_lock(lsm);
                obd_adjust_kms(exp, lsm, size, 0);
                lov_stripe_unlock(lsm);
                if (size > i_size_read(inode))
                        i_size_write(inode, size);
                SetPageUptodate(page);
        } else if (size > i_size_read(inode)) {
                /* this page beyond the pales of i_size, so it can't be
                 * truncated in ll_p_r_e during lock revoking. we must
                 * teardown our book-keeping here. */
                ll_removepage(page);
        }
        ll_inode_size_unlock(inode, 0);
        RETURN(rc);
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
        unsigned long ret = 0;
        ENTRY;

        /**
         * If read-ahead pages left are less than 1M, do not do read-ahead,
         * otherwise it will form small read RPC(< 1M), which hurt server
         * performance a lot.
         */
        ret = min(ra->ra_max_pages - atomic_read(&ra->ra_cur_pages), len);
        if ((int)ret < min((unsigned long)PTLRPC_MAX_BRW_PAGES, len))
                GOTO(out, ret = 0);

        if (atomic_add_return(ret, &ra->ra_cur_pages) > ra->ra_max_pages) {
                atomic_sub(ret, &ra->ra_cur_pages);
                ret = 0;
        }
out:
        RETURN(ret);
}

static void ll_ra_count_put(struct ll_sb_info *sbi, unsigned long len)
{
        struct ll_ra_info *ra = &sbi->ll_ra_info;
        atomic_sub(len, &ra->ra_cur_pages);
}

/* called for each page in a completed rpc.*/
int ll_ap_completion(void *data, int cmd, struct obdo *oa, int rc)
{
        struct ll_async_page *llap;
        struct page *page;
        struct obd_export *exp;
        obd_off end;
        int ret = 0;
        ENTRY;

        llap = LLAP_FROM_COOKIE(data);
        page = llap->llap_page;
        LASSERT(PageLocked(page));
        LASSERT(CheckWriteback(page,cmd));

        LL_CDEBUG_PAGE(D_PAGE, page, "completing cmd %d with %d\n", cmd, rc);

        if (cmd & OBD_BRW_READ && llap->llap_defer_uptodate) {
                ll_ra_count_put(ll_i2sbi(page->mapping->host), 1);
 
                LASSERT(lustre_handle_is_used(&llap->llap_lockh_granted));
                exp = ll_i2obdexp(page->mapping->host);
                end = ((loff_t)page->index) << CFS_PAGE_SHIFT;
                end += CFS_PAGE_SIZE - 1;
                obd_cancel(exp, ll_i2info(page->mapping->host)->lli_smd, LCK_PR,
                           &llap->llap_lockh_granted, OBD_FAST_LOCK, end);
        }

        if (rc == 0)  {
                if (cmd & OBD_BRW_READ) {
                        if (!llap->llap_defer_uptodate)
                                SetPageUptodate(page);
                } else {
                        llap->llap_write_queued = 0;
                }
                ClearPageError(page);
        } else {
                if (cmd & OBD_BRW_READ) {
                        llap->llap_defer_uptodate = 0;
                }
                SetPageError(page);
                if (rc == -ENOSPC)
                        set_bit(AS_ENOSPC, &page->mapping->flags);
                else
                        set_bit(AS_EIO, &page->mapping->flags);
        }

        /* be carefull about clear WB.
         * if WB will cleared after page lock is released - paralel IO can be
         * started before ap_make_ready is finished - so we will be have page
         * with PG_Writeback set from ->writepage() and completed READ which
         * clear this flag */
        if ((cmd & OBD_BRW_WRITE) && PageWriteback(page))
                end_page_writeback(page);

        unlock_page(page);

        if (cmd & OBD_BRW_WRITE) {
                llap_write_complete(page->mapping->host, llap);
                ll_try_done_writing(page->mapping->host);
        }

        page_cache_release(page);

        RETURN(ret);
}

static void __ll_put_llap(struct page *page)
{
        struct inode *inode = page->mapping->host;
        struct obd_export *exp;
        struct ll_async_page *llap;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_pglist_data *pd;
        int rc, cpu;
        ENTRY;

        exp = ll_i2obdexp(inode);
        if (exp == NULL) {
                CERROR("page %p ind %lu gave null export\n", page, page->index);
                EXIT;
                return;
        }

        llap = llap_from_page(page, LLAP_ORIGIN_REMOVEPAGE);
        if (IS_ERR(llap)) {
                CERROR("page %p ind %lu couldn't find llap: %ld\n", page,
                       page->index, PTR_ERR(llap));
                EXIT;
                return;
        }

        //llap_write_complete(inode, llap);
        rc = obd_teardown_async_page(exp, ll_i2info(inode)->lli_smd, NULL,
                                     llap->llap_cookie);
        if (rc != 0)
                CERROR("page %p ind %lu failed: %d\n", page, page->index, rc);

        /* this unconditional free is only safe because the page lock
         * is providing exclusivity to memory pressure/truncate/writeback..*/
        __clear_page_ll_data(page);

        lcounter_dec(&sbi->ll_async_page_count);
        cpu = llap->llap_pglist_cpu;
        pd = ll_pglist_cpu_lock(sbi, cpu);
        pd->llpd_gen++;
        pd->llpd_count--;
        if (!list_empty(&llap->llap_pglist_item))
                list_del_init(&llap->llap_pglist_item);
        ll_pglist_cpu_unlock(sbi, cpu);
        OBD_SLAB_FREE(llap, ll_async_page_slab, ll_async_page_slab_size);

        EXIT;
}

/* the kernel calls us here when a page is unhashed from the page cache.
 * the page will be locked and the kernel is holding a spinlock, so
 * we need to be careful.  we're just tearing down our book-keeping
 * here. */
void ll_removepage(struct page *page)
{
        struct ll_async_page *llap = llap_cast_private(page);
        ENTRY;

        LASSERT(!in_interrupt());

        /* sync pages or failed read pages can leave pages in the page
         * cache that don't have our data associated with them anymore */
        if (page_private(page) == 0) {
                EXIT;
                return;
        }

        ll_ra_accounting(llap, page->mapping);
        LL_CDEBUG_PAGE(D_PAGE, page, "being evicted\n");
        __ll_put_llap(page);

        EXIT;
}

static int ll_issue_page_read(struct obd_export *exp,
                              struct ll_async_page *llap,
                              struct obd_io_group *oig, int defer)
{
        struct page *page = llap->llap_page;
        int rc;

        page_cache_get(page);
        llap->llap_defer_uptodate = defer;
        llap->llap_ra_used = 0;
        rc = obd_queue_group_io(exp, ll_i2info(page->mapping->host)->lli_smd,
                                NULL, oig, llap->llap_cookie, OBD_BRW_READ, 0,
                                CFS_PAGE_SIZE, 0, ASYNC_COUNT_STABLE |
                                ASYNC_READY | ASYNC_URGENT);
        if (rc) {
                LL_CDEBUG_PAGE(D_ERROR, page, "read queue failed: rc %d\n", rc);
                page_cache_release(page);
        }
        RETURN(rc);
}

static void ll_ra_stats_inc_sbi(struct ll_sb_info *sbi, enum ra_stat which)
{
        LASSERTF(which >= 0 && which < _NR_RA_STAT, "which: %u\n", which);
        lprocfs_counter_incr(sbi->ll_ra_stats, which);
}

static void ll_ra_stats_inc(struct address_space *mapping, enum ra_stat which)
{
        struct ll_sb_info *sbi = ll_i2sbi(mapping->host);
        ll_ra_stats_inc_sbi(sbi, which);
}

void ll_ra_accounting(struct ll_async_page *llap, struct address_space *mapping)
{
        if (!llap->llap_defer_uptodate || llap->llap_ra_used)
                return;

        ll_ra_stats_inc(mapping, RA_STAT_DISCARDED);
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

struct ll_thread_data *ll_td_get()
{
#if 0
        struct ll_thread_data *ltd = current->journal_info;

        LASSERT(ltd == NULL || ltd->ltd_magic == LTD_MAGIC);
        return ltd;
#else
        return NULL;
#endif
}

void ll_td_set(struct ll_thread_data *ltd)
{
#if 0
        if (ltd == NULL) {
                ltd = current->journal_info;
                LASSERT(ltd == NULL || ltd->ltd_magic == LTD_MAGIC);
                current->journal_info = NULL;
                return;
        }

        LASSERT(current->journal_info == NULL);
        LASSERT(ltd->ltd_magic == LTD_MAGIC);
        current->journal_info = ltd;
#endif
}

static struct ll_readahead_state *ll_ras_get(struct file *f)
{
        struct ll_file_data       *fd;

        fd = LUSTRE_FPRIVATE(f);
        return &fd->fd_ras;
}

void ll_ra_read_init(struct file *f, struct ll_ra_read *rar,
                     loff_t offset, size_t count)
{
        struct ll_readahead_state *ras;

        ras = ll_ras_get(f);

        rar->lrr_start = offset >> CFS_PAGE_SHIFT;
        rar->lrr_count = (count + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;

        spin_lock(&ras->ras_lock);
        ras->ras_requests++;
        ras->ras_request_index = 0;
        ras->ras_consecutive_requests++;
        rar->lrr_reader = current;

        list_add(&rar->lrr_linkage, &ras->ras_read_beads);
        spin_unlock(&ras->ras_lock);
}

void ll_ra_read_ex(struct file *f, struct ll_ra_read *rar)
{
        struct ll_readahead_state *ras;

        ras = ll_ras_get(f);

        spin_lock(&ras->ras_lock);
        list_del_init(&rar->lrr_linkage);
        spin_unlock(&ras->ras_lock);
}

static struct ll_ra_read *ll_ra_read_get_locked(struct ll_readahead_state *ras)
{
        struct ll_ra_read *scan;

        list_for_each_entry(scan, &ras->ras_read_beads, lrr_linkage) {
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

        spin_lock(&ras->ras_lock);
        bead = ll_ra_read_get_locked(ras);
        spin_unlock(&ras->ras_lock);
        return bead;
}

static int ll_read_ahead_page(struct obd_export *exp, struct obd_io_group *oig,
                              pgoff_t index, struct address_space *mapping)
{
        struct ll_async_page *llap;
        struct page *page;
        unsigned int gfp_mask = 0;
        int rc = 0, flags = 0;
        struct lustre_handle lockh = { 0 };
        obd_off start, end;

        gfp_mask = GFP_HIGHUSER & ~__GFP_WAIT;
#ifdef __GFP_NOWARN
        gfp_mask |= __GFP_NOWARN;
#endif
        page = grab_cache_page_nowait_gfp(mapping, index, gfp_mask);
        if (page == NULL) {
                ll_ra_stats_inc(mapping, RA_STAT_FAILED_GRAB_PAGE);
                CDEBUG(D_READA, "g_c_p_n failed\n");
                return 0;
        }

        /* Check if page was truncated or reclaimed */
        if (page->mapping != mapping) {
                ll_ra_stats_inc(mapping, RA_STAT_WRONG_GRAB_PAGE);
                CDEBUG(D_READA, "g_c_p_n returned invalid page\n");
                GOTO(unlock_page, rc = 0);
        }

#if 0 /* the fast lock stored in ltd can't be guaranteed to be the lock used
       * by the llap returned by "llap_from_page_with_lockh" if there is a
       * ready llap, for lock check against readahead is disabled. 
       * see bug 16774/21252 */

        ltd = ll_td_get();
        if (ltd && ltd->lock_style > 0) {
                __u64 offset = ((loff_t)page->index) << CFS_PAGE_SHIFT;
                lockh = ltd2lockh(ltd, offset,
                                  offset + CFS_PAGE_SIZE - 1);
                if (ltd->lock_style == LL_LOCK_STYLE_FASTLOCK)
                        flags = OBD_FAST_LOCK;
        }
#endif

        /* we do this first so that we can see the page in the /proc
         * accounting */
        llap = llap_from_page_with_lockh(page, LLAP_ORIGIN_READAHEAD, &lockh,
                                         flags);
        if (IS_ERR(llap) || llap->llap_defer_uptodate) {
                /* bail out when we hit the end of the lock. */
                if (PTR_ERR(llap) == -ENOLCK) {
                        ll_ra_stats_inc(mapping, RA_STAT_FAILED_MATCH);
                        CDEBUG(D_READA | D_PAGE,
                               "Adding page to cache failed index "
                                "%ld\n", index);
                                CDEBUG(D_READA, "nolock page\n");
                                GOTO(unlock_page, rc = -ENOLCK);
                }
                CDEBUG(D_READA, "read-ahead page\n");
                GOTO(unlock_page, rc = 0);
        }

        /* skip completed pages */
        if (Page_Uptodate(page))
                GOTO(unlock_page, rc = 0);

        if (!lustre_handle_is_used(&lockh)) {
                start = ((loff_t)index) << CFS_PAGE_SHIFT;
                end = start + CFS_PAGE_SIZE - 1;
                rc = obd_get_lock(exp,
                                  ll_i2info(mapping->host)->lli_smd,
                                  &llap->llap_cookie, OBD_BRW_READ, 
                                  start, end, &lockh, OBD_FAST_LOCK);
                /* Is the lock being cancelling? */
                if (rc <= 0)
                        GOTO(unlock_page, rc = 0);
        }

        llap->llap_lockh_granted = lockh;

        rc = ll_issue_page_read(exp, llap, oig, 1);
        if (rc == 0) {
                LL_CDEBUG_PAGE(D_READA | D_PAGE, page, "started read-ahead\n");
                rc = 1;
        } else {
                llap->llap_lockh_granted.cookie = 0;
unlock_page:
                if (lustre_handle_is_used(&lockh))
                        ldlm_lock_decref(&lockh, LCK_PR);

                unlock_page(page);
                LL_CDEBUG_PAGE(D_READA | D_PAGE, page, "skipping read-ahead\n");
        }
        page_cache_release(page);
        return rc;
}

/* ra_io_arg will be filled in the beginning of ll_readahead with
 * ras_lock, then the following ll_read_ahead_pages will read RA
 * pages according to this arg, all the items in this structure are
 * counted by page index.
 */
struct ra_io_arg {
        unsigned long ria_start;  /* start offset of read-ahead*/
        unsigned long ria_end;    /* end offset of read-ahead*/
        /* If stride read pattern is detected, ria_stoff means where
         * stride read is started. Note: for normal read-ahead, the
         * value here is meaningless, and also it will not be accessed*/
        pgoff_t ria_stoff;
        /* ria_length and ria_pages are the length and pages length in the
         * stride I/O mode. And they will also be used to check whether
         * it is stride I/O read-ahead in the read-ahead pages*/
        unsigned long ria_length;
        unsigned long ria_pages;
};

#define RIA_DEBUG(ria)                                                \
        CDEBUG(D_READA, "rs %lu re %lu ro %lu rl %lu rp %lu\n",       \
        ria->ria_start, ria->ria_end, ria->ria_stoff, ria->ria_length,\
        ria->ria_pages)

#define INIT_RAS_WINDOW_PAGES PTLRPC_MAX_BRW_PAGES

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

static int ll_read_ahead_pages(struct obd_export *exp,
                               struct obd_io_group *oig,
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
                        rc = ll_read_ahead_page(exp, oig, page_idx, mapping);
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


/**
 * Current readahead process 
 *          read_syscall
 *              |
 *       ll_file_readv (init ll_readahead_state for the open file)
 *              |
 *              |
 *   |---> ll_readpage (read page)
 *   |          |
 *   |          |
 *   |     ras_update  (update read-ahead window according to read pattern) 
 *   |          | 
 *   |          |
 *   |--- ll_readahead  (read_ahead pages)
 *
 *
 *  During this process, ras_update controls how many ahead pages it should
 *  read by adjusting read-ahead window(RA window).The window is represented 
 *  by following three varibles (all these values are counted by pages)
 *        
 *      1. ras_window_start: start offset of the read-ahead window. It is 
 *                           initialized as the read offset, then as pages
 *                           are being read, it will be set as the last 
 *                           page(Note: it is 1M aligned, so it actually
 *                           is last_page_index & ~index & (~(256 - 1)); 
 *      
 *      2. ras_window_len: length of the read-ahead window. The read-ahead window
 *                         length is decided by two factors
 *                         
 *                         a. It is at least >= current read syscall length.
 *                         b. If continguous read is detected, (Note: it is syscall
 *                            continguous, intead of page-read contingous) the
 *                            read-ahead window len will be increased by 1M each
 *                            time.
 *                         c. If stride read pattern is detected, the read-ahead
 *                            window will also be increased 1M but by stride pattern.
 *                            stride pattern is defined by ras_stride_length, 
 *                            ras_stride_pages and ras_stride_gap. (see 
 *                            ll_readahead_states comments)
 *
 *      3. ras_next_readahead: current offset in the read-ahead window, i.e. where
 *                             ll_readahead will start in next next-ahead.
 * 
 *   
 *  Cache miss: If memory load is very high, it begins to evicted the page from cache,
 *  also includes read-ahead pages, once we found read-ahead page is being evicted before
 *  it is "really" accessed, it will reset the read-ahead window to the current read extent 
 *  i.e. from current page to the end of this read.
 *
 *  In flight read-ahead amount is controlled by 2 varible (read-ahead rate)
 *       ra_max_pages: how much max in-flight read-ahead pages on the client.
 *       ra_max_pages_per_file: how much max in-flight read-ahead pages per file.
 **/



static int ll_readahead(struct ll_readahead_state *ras,
                        struct obd_export *exp, struct address_space *mapping,
                        struct obd_io_group *oig, int flags)
{
        unsigned long start = 0, end = 0, reserved;
        unsigned long ra_end, len;
        struct inode *inode;
        struct lov_stripe_md *lsm;
        struct ll_ra_read *bead;
        struct ost_lvb lvb;
        struct ra_io_arg ria = { 0 };
        int ret = 0;
        __u64 kms;
        ENTRY;

        inode = mapping->host;
        lsm = ll_i2info(inode)->lli_smd;

        lov_stripe_lock(lsm);
        inode_init_lvb(inode, &lvb);
        obd_merge_lvb(ll_i2obdexp(inode), lsm, &lvb, 1);
        kms = lvb.lvb_size;
        lov_stripe_unlock(lsm);
        if (kms == 0) {
                ll_ra_stats_inc(mapping, RA_STAT_ZERO_LEN);
                RETURN(0);
        }

        spin_lock(&ras->ras_lock);
        bead = ll_ra_read_get_locked(ras);
        /* Enlarge the RA window to encompass the full read */
        if (bead != NULL && ras->ras_window_start + ras->ras_window_len <
            bead->lrr_start + bead->lrr_count) {
                obd_off read_end = ((obd_off)(bead->lrr_start +
                                              bead->lrr_count))<<CFS_PAGE_SHIFT;
                obd_extent_calc(exp, lsm, OBD_CALC_STRIPE_RPC_END_ALIGN,
                                &read_end);
                ras->ras_window_len = ((read_end + 1) >> CFS_PAGE_SHIFT) -
                                      ras->ras_window_start;
        }
        /* Reserve a part of the read-ahead window that we'll be issuing */
        if (ras->ras_window_len) {
                start = ras->ras_next_readahead;
                end = ras->ras_window_start + ras->ras_window_len - 1;
        }
        if (end != 0) {
                /* Truncate RA window to end of file */
                end = min(end, (unsigned long)((kms - 1) >> CFS_PAGE_SHIFT));
                ras->ras_next_readahead = max(end, end + 1);
                RAS_CDEBUG(ras);
        }
        ria.ria_start = start;
        ria.ria_end = end;
        /* If stride I/O mode is detected, get stride window*/
        if (stride_io_mode(ras)) {
                ria.ria_stoff = ras->ras_stride_offset;
                ria.ria_length = ras->ras_stride_length;
                ria.ria_pages = ras->ras_stride_pages;
        }
        spin_unlock(&ras->ras_lock);

        if (end == 0) {
                ll_ra_stats_inc(mapping, RA_STAT_ZERO_WINDOW);
                RETURN(0);
        }

        len = ria_page_count(&ria);
        if (len == 0)
                RETURN(0);

        reserved = ll_ra_count_get(ll_i2sbi(inode), len);
        if (reserved < len)
                ll_ra_stats_inc(mapping, RA_STAT_MAX_IN_FLIGHT);

        CDEBUG(D_READA, "reserved page %lu \n", reserved);

        ret = ll_read_ahead_pages(exp, oig, &ria, &reserved, mapping, &ra_end);

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
               ra_end, end, ria.ria_end);

        if (ra_end != (end + 1)) {
                spin_lock(&ras->ras_lock);
                if (ra_end < ras->ras_next_readahead &&
                    index_in_window(ra_end, ras->ras_window_start, 0,
                                    ras->ras_window_len)) {
                        ras->ras_next_readahead = ra_end;
                        RAS_CDEBUG(ras);
                }
                spin_unlock(&ras->ras_lock);
        }

        RETURN(ret);
}

static void ras_set_start(struct ll_readahead_state *ras, unsigned long index)
{
        /* Since stride readahead is sentivite to the offset
         * of read-ahead, so we use original offset here,
         * instead of ras_window_start, which is 1M aligned*/
        if (stride_io_mode(ras))
                ras->ras_window_start = index;
        else
                ras->ras_window_start = index & (~(INIT_RAS_WINDOW_PAGES - 1));
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
        spin_lock_init(&ras->ras_lock);
        ras_reset(ras, 0);
        ras->ras_requests = 0;
        INIT_LIST_HEAD(&ras->ras_read_beads);
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
 * the stride I/O pattern.
 *
 *      |------------------------|------------------------|--------------------|
 * ras_stride_offset      ras_window_start          ras_window_end
 *                               |<---ras_window_len----->|<---ras_inc_len---->|
 *
 * ras_stride_offset: where the stride IO mode started,
 * Note: stride_page is always in front of stride_gap page, see comments in
 * ll_readahead_states and stride_pg_count
 *
 * This function calculates how much ras_window should increase(ras_inc_len)
 * according to @Inc_len, Note: in stride read-ahead algorithm, stride_gap is
 * also acconted in the ras_window_len, so basically,
 *
 * ras_inc_len = (inc_len/ stride_page) * (stride_page + stride_gap)
 *
 * */
static void ras_stride_increase_window(struct ll_readahead_state *ras,
                                       struct ll_ra_info *ra,
                                       unsigned long inc_len)
{
        unsigned long left, step, window_len;
        unsigned long stride_len;

        LASSERT(ras->ras_stride_length > 0);
        LASSERTF(ras->ras_window_start + ras->ras_window_len
                 >= ras->ras_stride_offset, "window_start %lu, window_len %lu"
                 " stride_offset %lu sp %lu sl %lu\n", ras->ras_window_start,
                 ras->ras_window_len, ras->ras_stride_offset, ras->ras_stride_pages,
                 ras->ras_stride_length);

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
        __u64 step = INIT_RAS_WINDOW_PAGES;

        if (stride_io_mode(ras))
                ras_stride_increase_window(ras, ra, (unsigned long)step);
        else
                ras->ras_window_len = min(ras->ras_window_len +
                                          (unsigned long)step,
                                          ra->ra_max_pages);
}

static void ras_update(struct ll_sb_info *sbi, struct inode *inode,
                       struct ll_readahead_state *ras, unsigned long index,
                       unsigned hit)
{
        struct ll_ra_info *ra = &sbi->ll_ra_info;
        int zero = 0, stride_detect = 0, ra_miss = 0;
        ENTRY;

        spin_lock(&ras->ras_lock);

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
                       ra->ra_max_read_ahead_whole_pages,
                       ra->ra_max_pages_per_file);

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
        ras->ras_next_readahead = max(ras->ras_window_start,
                                      ras->ras_next_readahead);
        RAS_CDEBUG(ras);

        /* Trigger RA in the mmap case where ras_consecutive_requests
         * is not incremented and thus can't be used to trigger RA */
        if (!ras->ras_window_len && ras->ras_consecutive_pages == 4) {
                ras->ras_window_len = INIT_RAS_WINDOW_PAGES;
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
                ras->ras_window_len = INIT_RAS_WINDOW_PAGES;
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
        spin_unlock(&ras->ras_lock);
        return;
}

int ll_writepage(struct page *page)
{
        struct inode *inode = page->mapping->host;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_export *exp;
        struct ll_async_page *llap;
        struct ll_thread_data *ltd;
        struct lustre_handle *lockh = NULL;
        int rc = 0;
        ENTRY;

        LASSERT(PageLocked(page));

        exp = ll_i2obdexp(inode);
        if (exp == NULL)
                GOTO(out, rc = -EINVAL);

        ltd = ll_td_get();
        /* currently, no FAST lock in write path */
        if (ltd && ltd->lock_style == LL_LOCK_STYLE_TREELOCK) {
                __u64 offset = ((loff_t)page->index) << CFS_PAGE_SHIFT;
                lockh = ltd2lockh(ltd, offset, offset + CFS_PAGE_SIZE - 1);
        }

        llap = llap_from_page_with_lockh(page, LLAP_ORIGIN_WRITEPAGE, lockh, 0);
        if (IS_ERR(llap))
                GOTO(out, rc = PTR_ERR(llap));

        LASSERT(!PageWriteback(page));
        set_page_writeback(page);

        page_cache_get(page);
        if (llap->llap_write_queued) {
                LL_CDEBUG_PAGE(D_PAGE, page, "marking urgent\n");
                rc = obd_set_async_flags(exp, lli->lli_smd, NULL,
                                         llap->llap_cookie,
                                         ASYNC_READY | ASYNC_URGENT);
        } else {
                rc = queue_or_sync_write(exp, inode, llap, CFS_PAGE_SIZE,
                                         ASYNC_READY | ASYNC_URGENT);
        }
        if (rc) {
                /* re-dirty page on error so it retries write */
                if (PageWriteback(page))
                        end_page_writeback(page);

                /* resend page only for not started IO*/
                if (!PageError(page))
                        ll_redirty_page(page);

                page_cache_release(page);
        }
out:
        if (rc) {
                if (!lli->lli_async_rc)
                        lli->lli_async_rc = rc;
                /* resend page only for not started IO*/
                unlock_page(page);
        }
        RETURN(rc);
}

/*
 * for now we do our readpage the same on both 2.4 and 2.5.  The kernel's
 * read-ahead assumes it is valid to issue readpage all the way up to
 * i_size, but our dlm locks make that not the case.  We disable the
 * kernel's read-ahead and do our own by walking ahead in the page cache
 * checking for dlm lock coverage.  the main difference between 2.4 and
 * 2.6 is how read-ahead gets batched and issued, but we're using our own,
 * so they look the same.
 */
int ll_readpage(struct file *filp, struct page *page)
{
        struct ll_file_data *fd = LUSTRE_FPRIVATE(filp);
        struct inode *inode = page->mapping->host;
        struct obd_export *exp;
        struct ll_async_page *llap;
        struct obd_io_group *oig = NULL;
        struct lustre_handle *lockh = NULL;
        int rc, flags = 0;
        ENTRY;

        LASSERT(PageLocked(page));
        LASSERT(!PageUptodate(page));
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),offset=%Lu=%#Lx\n",
               inode->i_ino, inode->i_generation, inode,
               (((loff_t)page->index) << CFS_PAGE_SHIFT),
               (((loff_t)page->index) << CFS_PAGE_SHIFT));
        LASSERT(atomic_read(&filp->f_dentry->d_inode->i_count) > 0);

        if (!ll_i2info(inode)->lli_smd) {
                /* File with no objects - one big hole */
                /* We use this just for remove_from_page_cache that is not
                 * exported, we'd make page back up to date. */
                ll_truncate_complete_page(page);
                clear_page(kmap(page));
                kunmap(page);
                SetPageUptodate(page);
                unlock_page(page);
                RETURN(0);
        }

        rc = oig_init(&oig);
        if (rc < 0)
                GOTO(out, rc);

        exp = ll_i2obdexp(inode);
        if (exp == NULL)
                GOTO(out, rc = -EINVAL);

        if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
                lockh = &fd->fd_cwlockh;
        } else {
                struct ll_thread_data *ltd;
                ltd = ll_td_get();
                if (ltd && ltd->lock_style > 0) {
                        __u64 offset = ((loff_t)page->index) << CFS_PAGE_SHIFT;
                        lockh = ltd2lockh(ltd, offset,
                                          offset + CFS_PAGE_SIZE - 1);
                        if (ltd->lock_style == LL_LOCK_STYLE_FASTLOCK)
                                flags = OBD_FAST_LOCK;
                }
        }

        llap = llap_from_page_with_lockh(page, LLAP_ORIGIN_READPAGE, lockh,
                                         flags);
        if (IS_ERR(llap)) {
                if (PTR_ERR(llap) == -ENOLCK) {
                        CWARN("ino %lu page %lu (%llu) not covered by "
                              "a lock (mmap?).  check debug logs.\n",
                              inode->i_ino, page->index,
                              (long long)page->index << PAGE_CACHE_SHIFT);
                }
                GOTO(out, rc = PTR_ERR(llap));
        }

        if (ll_i2sbi(inode)->ll_ra_info.ra_max_pages_per_file)
                ras_update(ll_i2sbi(inode), inode, &fd->fd_ras, page->index,
                           llap->llap_defer_uptodate);


        if (llap->llap_defer_uptodate) {
                /* This is the callpath if we got the page from a readahead */
                llap->llap_ra_used = 1;
                rc = ll_readahead(&fd->fd_ras, exp, page->mapping, oig,
                                  fd->fd_flags);
                if (rc > 0)
                        obd_trigger_group_io(exp, ll_i2info(inode)->lli_smd,
                                             NULL, oig);
                LL_CDEBUG_PAGE(D_PAGE, page, "marking uptodate from defer\n");
                SetPageUptodate(page);
                unlock_page(page);
                GOTO(out_oig, rc = 0);
        }

        rc = ll_issue_page_read(exp, llap, oig, 0);
        if (rc)
                GOTO(out, rc);

        LL_CDEBUG_PAGE(D_PAGE, page, "queued readpage\n");
        /* We have just requested the actual page we want, see if we can tack
         * on some readahead to that page's RPC before it is sent. */
        if (ll_i2sbi(inode)->ll_ra_info.ra_max_pages_per_file)
                ll_readahead(&fd->fd_ras, exp, page->mapping, oig,
                             fd->fd_flags);

        rc = obd_trigger_group_io(exp, ll_i2info(inode)->lli_smd, NULL, oig);

out:
        if (rc)
                unlock_page(page);
out_oig:
        if (oig != NULL)
                oig_release(oig);
        RETURN(rc);
}

