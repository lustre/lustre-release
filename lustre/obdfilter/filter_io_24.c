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
 *
 * lustre/obdfilter/filter_io_24.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/pagemap.h> // XXX kill me soon
#include <linux/version.h>

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/iobuf.h>
#include <linux/locks.h>

#include <obd_class.h>
#include <lustre_fsfilt.h>
#include "filter_internal.h"

/* Bug 2254 -- this is better done in ext3_map_inode_page, but this
 * workaround will suffice until everyone has upgraded their kernels */
static void check_pending_bhs(unsigned long *blocks, int nr_pages, dev_t dev,
                              int size)
{
#if (LUSTRE_KERNEL_VERSION < 32)
        struct buffer_head *bh;
        int i;

        for (i = 0; i < nr_pages; i++) {
                bh = get_hash_table(dev, blocks[i], size);
                if (bh == NULL)
                        continue;
                if (!buffer_dirty(bh)) {
                        put_bh(bh);
                        continue;
                }
                mark_buffer_clean(bh);
                wait_on_buffer(bh);
                clear_bit(BH_Req, &bh->b_state);
                __brelse(bh);
        }
#endif
}

/* when brw_kiovec() is asked to read from block -1UL it just zeros
 * the page.  this gives us a chance to verify the write mappings
 * as well */
static int filter_cleanup_mappings(int rw, struct kiobuf *iobuf,
                                   struct inode *inode)
{
        int i, blocks_per_page_bits = CFS_PAGE_SHIFT - inode->i_blkbits;
        ENTRY;

        for (i = 0 ; i < iobuf->nr_pages << blocks_per_page_bits; i++) {
                if (KIOBUF_GET_BLOCKS(iobuf)[i] > 0)
                        continue;

                if (rw == OBD_BRW_WRITE)
                        RETURN(-EINVAL);

                KIOBUF_GET_BLOCKS(iobuf)[i] = -1UL;
        }
        RETURN(0);
}

#if 0
static void dump_page(int rw, unsigned long block, struct page *page)
{
        char *blah = kmap(page);
        CDEBUG(D_PAGE, "rw %d block %lu: %02x %02x %02x %02x\n", rw, block,
                       blah[0], blah[1], blah[2], blah[3]);
        kunmap(page);
}
#endif

/* These are our hacks to keep our directio/bh IO coherent with ext3's
 * page cache use.  Most notably ext3 reads file data into the page
 * cache when it is zeroing the tail of partial-block truncates and
 * leaves it there, sometimes generating io from it at later truncates.
 * This removes the partial page and its buffers from the page cache,
 * so it should only ever cause a wait in rare cases, as otherwise we
 * always do full-page IO to the OST.
 *
 * The call to truncate_complete_page() will call journal_flushpage() to
 * free the buffers and drop the page from cache.  The buffers should not
 * be dirty, because we already called fdatasync/fdatawait on them.
 */
static int filter_sync_inode_data(struct inode *inode)
{
        int rc, rc2;

        /* This is nearly generic_osync_inode, without the waiting on the inode
        rc = generic_osync_inode(inode, inode->i_mapping,
                                 OSYNC_DATA|OSYNC_METADATA);
         */
        rc = filemap_fdatasync(inode->i_mapping);
        rc2 = fsync_inode_data_buffers(inode);
        if (rc == 0)
                rc = rc2;
        rc2 = filemap_fdatawait(inode->i_mapping);
        if (rc == 0)
                rc = rc2;

        return rc;
}

static int filter_clear_page_cache(struct inode *inode, struct kiobuf *iobuf)
{
        struct page *page;
        int i, rc;

        check_pending_bhs(KIOBUF_GET_BLOCKS(iobuf), iobuf->nr_pages,
                          inode->i_dev, 1 << inode->i_blkbits);

        rc = filter_sync_inode_data(inode);
        if (rc != 0)
                RETURN(rc);

        /* be careful to call this after fsync_inode_data_buffers has waited
         * for IO to complete before we evict it from the cache */
        for (i = 0; i < iobuf->nr_pages ; i++) {
                page = find_lock_page(inode->i_mapping,
                                      iobuf->maplist[i]->index);
                if (page == NULL)
                        continue;
                if (page->mapping != NULL) {
                        /* Now that the only source of such pages in truncate
                         * path flushes these pages to disk and and then
                         * discards, this is error condition */
                        CERROR("Data page in page cache during write!\n");
                        ll_truncate_complete_page(page);
                }

                unlock_page(page);
                page_cache_release(page);
        }

        return 0;
}

int filter_clear_truncated_page(struct inode *inode)
{
        struct page *page;
        int rc;

        /* Truncate on page boundary, so nothing to flush? */
        if (!(i_size_read(inode) & ~CFS_PAGE_MASK))
                return 0;

        rc = filter_sync_inode_data(inode);
        if (rc != 0)
                RETURN(rc);

        /* be careful to call this after fsync_inode_data_buffers has waited
         * for IO to complete before we evict it from the cache */
        page = find_lock_page(inode->i_mapping,
                              i_size_read(inode) >> CFS_PAGE_SHIFT);
        if (page) {
                if (page->mapping != NULL)
                        ll_truncate_complete_page(page);

                unlock_page(page);
                page_cache_release(page);
        }

        return 0;
}

/* Must be called with i_sem taken for writes; this will drop it */
int filter_direct_io(int rw, struct dentry *dchild, struct filter_iobuf *buf,
                     struct obd_export *exp, struct iattr *attr,
                     struct obd_trans_info *oti, void **wait_handle)
{
        struct obd_device *obd = exp->exp_obd;
        struct inode *inode = dchild->d_inode;
        struct kiobuf *iobuf = (void *)buf;
        int rc, create = (rw == OBD_BRW_WRITE), committed = 0;
        int blocks_per_page = CFS_PAGE_SIZE >> inode->i_blkbits, cleanup_phase = 0;
        struct semaphore *sem = NULL;
        ENTRY;

        LASSERTF(rw == OBD_BRW_WRITE || rw == OBD_BRW_READ, "%x\n", rw);

        if (iobuf->nr_pages == 0)
                GOTO(cleanup, rc = 0);

        if (iobuf->nr_pages * blocks_per_page > KIO_MAX_SECTORS)
                GOTO(cleanup, rc = -EINVAL);

        if (iobuf->nr_pages * blocks_per_page >
            OBDFILTER_CREATED_SCRATCHPAD_ENTRIES)
                GOTO(cleanup, rc = -EINVAL);

        cleanup_phase = 1;

        rc = lock_kiovec(1, &iobuf, 1);
        if (rc < 0)
                GOTO(cleanup, rc);
        cleanup_phase = 2;

        if (rw == OBD_BRW_WRITE) {
                create = 1;
                sem = &obd->u.filter.fo_alloc_lock;
        }
        rc = fsfilt_map_inode_pages(obd, inode, iobuf->maplist,
                                    iobuf->nr_pages, KIOBUF_GET_BLOCKS(iobuf),
                                    obdfilter_created_scratchpad, create, sem);
        if (rc)
                GOTO(cleanup, rc);

        rc = filter_cleanup_mappings(rw, iobuf, inode);
        if (rc)
                GOTO(cleanup, rc);

        if (rw == OBD_BRW_WRITE) {
                if (rc == 0) {
                        filter_tally(exp, iobuf->maplist, iobuf->nr_pages,
                                     KIOBUF_GET_BLOCKS(iobuf), blocks_per_page,
                                     1);

                        if (attr->ia_size > i_size_read(inode))
                                attr->ia_valid |= ATTR_SIZE;
                        rc = fsfilt_setattr(obd, dchild,
                                            oti->oti_handle, attr, 0);
                        if (rc)
                                GOTO(cleanup, rc);
                }

                up(&inode->i_sem);
                cleanup_phase = 3;

                rc = filter_finish_transno(exp, oti, 0, 0);
                if (rc)
                        GOTO(cleanup, rc);

                rc = fsfilt_commit_async(obd,inode,oti->oti_handle,wait_handle);
                committed = 1;
                if (rc)
                        GOTO(cleanup, rc);
        } else {
                filter_tally(exp, iobuf->maplist, iobuf->nr_pages,
                             KIOBUF_GET_BLOCKS(iobuf), blocks_per_page, 0);
        }

        rc = filter_clear_page_cache(inode, iobuf);
        if (rc < 0)
                GOTO(cleanup, rc);

        rc = fsfilt_send_bio(rw, obd, inode, iobuf);

        CDEBUG(D_INFO, "tried to %s %d pages, rc = %d\n",
               rw & OBD_BRW_WRITE ? "write" : "read", iobuf->nr_pages, rc);

        if (rc > 0)
                rc = 0;

        EXIT;
cleanup:
        if (!committed && (rw == OBD_BRW_WRITE)) {
                int err = fsfilt_commit_async(obd, inode,
                                              oti->oti_handle, wait_handle);
                if (err)
                        CERROR("can't close transaction: %d\n", err);
                /*
                 * this is error path, so we prefer to return
                 * original error, not this one
                 */
        }

        switch(cleanup_phase) {
        case 3:
        case 2:
                unlock_kiovec(1, &iobuf);
        case 1:
        case 0:
                if (cleanup_phase != 3 && rw == OBD_BRW_WRITE)
                        up(&inode->i_sem);
                break;
        default:
                CERROR("corrupt cleanup_phase (%d)?\n", cleanup_phase);
                LBUG();
                break;
        }
        return rc;
}

/* See if there are unallocated parts in given file region */
int filter_range_is_mapped(struct inode *inode, obd_size offset, int len)
{
        int (*fs_bmap)(struct address_space *, long) =
                inode->i_mapping->a_ops->bmap;
        int j;

        /* We can't know if the range is mapped already or not */
        if (fs_bmap == NULL)
                return 0;

        offset >>= inode->i_blkbits;
        len >>= inode->i_blkbits;

        for (j = 0; j < len; j++)
                if (fs_bmap(inode->i_mapping, offset + j) == 0)
                        return 0;

        return 1;
}

/* some kernels require alloc_kiovec callers to zero members through the use of
 * map_user_kiobuf and unmap_.. we don't use those, so we have a little helper
 * that makes sure we don't break the rules. */
static void clear_kiobuf(struct kiobuf *iobuf)
{
        int i;

        for (i = 0; i < iobuf->array_len; i++)
                iobuf->maplist[i] = NULL;

        iobuf->nr_pages = 0;
        iobuf->offset = 0;
        iobuf->length = 0;
}

struct filter_iobuf *filter_alloc_iobuf(struct filter_obd *filter,
                                        int rw, int num_pages)
{
        struct kiobuf *iobuf;
        int rc;
        ENTRY;

        LASSERTF(rw == OBD_BRW_WRITE || rw == OBD_BRW_READ, "%x\n", rw);

        rc = alloc_kiovec(1, &iobuf);
        if (rc)
                RETURN(ERR_PTR(rc));

        rc = expand_kiobuf(iobuf, num_pages);
        if (rc) {
                free_kiovec(1, &iobuf);
                RETURN(ERR_PTR(rc));
        }

#ifdef HAVE_KIOBUF_DOVARY
        iobuf->dovary = 0; /* this prevents corruption, not present in 2.4.20 */
#endif
        clear_kiobuf(iobuf);
        RETURN((void *)iobuf);
}

void filter_free_iobuf(struct filter_iobuf *buf)
{
        struct kiobuf *iobuf = (void *)buf;

        clear_kiobuf(iobuf);
        free_kiovec(1, &iobuf);
}

void filter_iobuf_put(struct filter_obd *filter, struct filter_iobuf *iobuf,
                      struct obd_trans_info *oti)
{
        int thread_id = (oti && oti->oti_thread) ?
                        oti->oti_thread->t_id : -1;

        if (unlikely(thread_id < 0)) {
                filter_free_iobuf(iobuf);
                return;
        }

        LASSERTF(filter->fo_iobuf_pool[thread_id] == iobuf,
                 "iobuf mismatch for thread %d: pool %p iobuf %p\n",
                 thread_id, filter->fo_iobuf_pool[thread_id], iobuf);
        clear_kiobuf((void *)iobuf);
}

int filter_iobuf_add_page(struct obd_device *obd, struct filter_iobuf *buf,
                           struct inode *inode, struct page *page)
{
        struct kiobuf *iobuf = (void *)buf;

        iobuf->maplist[iobuf->nr_pages++] = page;
        iobuf->length += CFS_PAGE_SIZE;

        return 0;
}

int filter_commitrw_write(struct obd_export *exp, struct obdo *oa, int objcount,
                          struct obd_ioobj *obj, int niocount,
                          struct niobuf_local *res, struct obd_trans_info *oti,
                          int rc)
{
        struct obd_device *obd = exp->exp_obd;
        struct lvfs_run_ctxt saved;
        struct niobuf_local *lnb;
        struct fsfilt_objinfo fso;
        struct iattr iattr = { 0 };
        void *iobuf = NULL;
        struct inode *inode = NULL;
        int i, n, cleanup_phase = 0, err;
        unsigned long now = jiffies; /* DEBUGGING OST TIMEOUTS */
        void *wait_handle;
        ENTRY;
        LASSERT(oti != NULL);
        LASSERT(objcount == 1);
        LASSERT(current->journal_info == NULL);

        if (rc != 0)
                GOTO(cleanup, rc);

        iobuf = filter_iobuf_get(&obd->u.filter, oti);
        if (IS_ERR(iobuf))
                GOTO(cleanup, rc = PTR_ERR(iobuf));
        cleanup_phase = 1;

        fso.fso_dentry = res->dentry;
        fso.fso_bufcnt = obj->ioo_bufcnt;
        inode = res->dentry->d_inode;

        for (i = 0, lnb = res, n = 0; i < obj->ioo_bufcnt; i++, lnb++) {
                loff_t this_size;

                /* If overwriting an existing block, we don't need a grant */
                if (!(lnb->flags & OBD_BRW_GRANTED) && lnb->rc == -ENOSPC &&
                    filter_range_is_mapped(inode, lnb->offset, lnb->len))
                        lnb->rc = 0;

                if (lnb->rc) /* ENOSPC, network RPC error */
                        continue;

                filter_iobuf_add_page(obd, iobuf, inode, lnb->page);

                /* We expect these pages to be in offset order, but we'll
                 * be forgiving */
                this_size = lnb->offset + lnb->len;
                if (this_size > iattr.ia_size)
                        iattr.ia_size = this_size;
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        cleanup_phase = 2;

        down(&inode->i_sem);
        oti->oti_handle = fsfilt_brw_start(obd, objcount, &fso, niocount, res,
                                           oti);
        if (IS_ERR(oti->oti_handle)) {
                up(&inode->i_sem);
                rc = PTR_ERR(oti->oti_handle);
                CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                       "error starting transaction: rc = %d\n", rc);
                oti->oti_handle = NULL;
                GOTO(cleanup, rc);
        }

        fsfilt_check_slow(obd, now, "brw_start");

        i = OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME;

        /* If the inode still has SUID+SGID bits set (see filter_precreate())
         * then we will accept the UID+GID if sent by the client for
         * initializing the ownership of this inode.  We only allow this to
         * happen once (so clear these bits) and later only allow setattr. */
        if (inode->i_mode & S_ISUID)
                i |= OBD_MD_FLUID;
        if (inode->i_mode & S_ISGID)
                i |= OBD_MD_FLGID;

        iattr_from_obdo(&iattr, oa, i);
        if (iattr.ia_valid & (ATTR_UID | ATTR_GID)) {
                CDEBUG(D_INODE, "update UID/GID to %lu/%lu\n",
                       (unsigned long)oa->o_uid, (unsigned long)oa->o_gid);

                cfs_cap_raise(CFS_CAP_SYS_RESOURCE);

                iattr.ia_valid |= ATTR_MODE;
                iattr.ia_mode = inode->i_mode;
                if (iattr.ia_valid & ATTR_UID)
                        iattr.ia_mode &= ~S_ISUID;
                if (iattr.ia_valid & ATTR_GID)
                        iattr.ia_mode &= ~S_ISGID;

                rc = filter_update_fidea(exp, inode, oti->oti_handle, oa);
        }

        /* filter_direct_io drops i_sem */
        rc = filter_direct_io(OBD_BRW_WRITE, res->dentry, iobuf, exp, &iattr,
                              oti, &wait_handle);
        if (rc == 0)
                obdo_from_inode(oa, inode, FILTER_VALID_FLAGS);

        fsfilt_check_slow(obd, now, "direct_io");

        err = fsfilt_commit_wait(obd, inode, wait_handle);
        if (err) {
                CERROR("Failure to commit OST transaction (%d)?\n", err);
                rc = err;
        }
        if (obd->obd_replayable && !rc)
                LASSERTF(oti->oti_transno <= obd->obd_last_committed,
                         "oti_transno "LPU64" last_committed "LPU64"\n",
                         oti->oti_transno, obd->obd_last_committed);
        fsfilt_check_slow(obd, now, "commitrw commit");

cleanup:
        filter_grant_commit(exp, niocount, res);

        switch (cleanup_phase) {
        case 2:
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                LASSERT(current->journal_info == NULL);
        case 1:
                filter_iobuf_put(&obd->u.filter, iobuf, oti);
        case 0:
                /*
                 * lnb->page automatically returns back into per-thread page
                 * pool (bug 5137)
                 */
                f_dput(res->dentry);
        }

        RETURN(rc);
}
