/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite I/O page cache routines for the 2.5/2.6 kernel generation
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/config.h>
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
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>
#include "llite_internal.h"
#include <linux/lustre_compat25.h>

/* in 2.5 we hope that significant read traffic will come through
 * readpages and will be nicely batched by read-ahead, this is just
 * to pick up the rest.  */
static int ll_readpage_26(struct file *file, struct page *page)
{
        ENTRY;

        CDEBUG(D_CACHE, "page %p ind %lu inode %p\n", page, page->index,
                        page->mapping->host);

        LASSERT(PageLocked(page));
        LASSERT(!PageUptodate(page));
        LASSERT(page->private == 0);

        /* put it in the list that lliod will use */
        page_cache_get(page);
        lliod_give_page(page->mapping->host, page, OBD_BRW_READ);
        lliod_wakeup(page->mapping->host);

        RETURN(0);
}

void ll_end_writeback_26(struct inode *inode, struct page *page)
{
        int rc;
        ENTRY;
        LASSERT(PageWriteback(page));
        rc = ll_clear_dirty_pages(ll_i2obdconn(inode),
                                  ll_i2info(inode)->lli_smd,
                                  page->index, page->index);
        LASSERT(rc == 0);
        end_page_writeback(page);
        EXIT;
}

static int ll_writepage_26(struct page *page, struct writeback_control *wbc)
{
        struct inode *inode = page->mapping->host;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obdo oa;
        struct obd_export *exp;
        struct obd_client_page *ocp;
        int rc;
        ENTRY;

        LASSERT(PageLocked(page));
        LASSERT(!PageWriteback(page));

        ocp = ocp_alloc(page);
        if (IS_ERR(ocp)) 
                GOTO(out, rc = PTR_ERR(ocp));

        ocp->ocp_callback = ll_complete_writepage_26;
        ocp->ocp_flag = OBD_BRW_CREATE|OBD_BRW_FROM_GRANT;

        /* tell the vm that we're busy with the page */
        SetPageWriteback(page);
        unlock_page(page);

        /* XXX clean up the ocp? */ 
        rc = ll_writepage_common(page);
        if (rc)
                RETURN(rc);
        ll_local_cache_started_io(1);

        ll_writeback_from_dirty(inode);

        RETURN(0);
}

static int ll_writepages(struct address_space *mapping, 
                         struct writeback_control *wbc)
{
        struct ll_inode_info *lli = ll_i2info(mapping->host);
        int rc;
        ENTRY;

        atomic_inc(&lli->lli_in_writepages);

        rc = mpage_writepages(mapping, wbc, NULL);

        if (atomic_dec_and_test(&lli->lli_in_writepages)) 
                lliod_wakeup(mapping->host);

        RETURN(rc);
}

#if 0 /* XXX need to complete this */
static int ll_direct_IO(int rw, struct inode *inode, struct kiobuf *iobuf,
                        unsigned long blocknr, int blocksize)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct brw_page *pga;
        struct ptlrpc_request_set *set;
        struct obdo oa;
        int length, i, flags, rc = 0;
        loff_t offset;
        ENTRY;

        if (!lsm || !lsm->lsm_object_id)
                RETURN(-EBADF);

        if ((iobuf->offset & (blocksize - 1)) ||
            (iobuf->length & (blocksize - 1)))
                RETURN(-EINVAL);

        set = ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        OBD_ALLOC(pga, sizeof(*pga) * iobuf->nr_pages);
        if (!pga) {
                ptlrpc_set_destroy(set);
                RETURN(-ENOMEM);
        }

        flags = (rw == WRITE ? OBD_BRW_CREATE : 0) /* | OBD_BRW_DIRECTIO */;
        offset = ((obd_off)blocknr << inode->i_blkbits);
        length = iobuf->length;

        for (i = 0, length = iobuf->length; length > 0;
             length -= pga[i].count, offset += pga[i].count, i++) { /*i last!*/
                pga[i].pg = iobuf->maplist[i];
                pga[i].off = offset;
                /* To the end of the page, or the length, whatever is less */
                pga[i].count = min_t(int, PAGE_SIZE - (offset & ~PAGE_MASK),
                                     length);
                pga[i].flag = flags;
                if (rw == READ) {
                        //POISON(kmap(iobuf->maplist[i]), 0xc5, PAGE_SIZE);
                        //kunmap(iobuf->maplist[i]);
                }
        }

        oa.o_id = lsm->lsm_object_id;
        oa.o_valid = OBD_MD_FLID;
        obdo_from_inode(&oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                    OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        if (rw == WRITE)
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_DIRECT_WRITE, iobuf->length);
        else
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_DIRECT_READ, iobuf->length);
        rc = obd_brw_async(rw == WRITE ? OBD_BRW_WRITE : OBD_BRW_READ,
                           ll_i2obdconn(inode), &oa, lsm, iobuf->nr_pages, pga,
                           set, NULL);
        if (rc) {
                CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                       "error from obd_brw_async: rc = %d\n", rc);
        } else {
                rc = ptlrpc_set_wait(set);
                if (rc)
                        CERROR("error from callback: rc = %d\n", rc);
        }
        ptlrpc_set_destroy(set);
        if (rc == 0)
                rc = iobuf->length;

        OBD_FREE(pga, sizeof(*pga) * iobuf->nr_pages);
        RETURN(rc);
}
#endif

struct address_space_operations ll_aops = {
        readpage: ll_readpage_26,
#if 0
        direct_IO: ll_direct_IO_26,
#endif
        writepage: ll_writepage_26,
        writepages: ll_writepages,
        set_page_dirty: __set_page_dirty_nobuffers,
        sync_page: block_sync_page,
        prepare_write: ll_prepare_write,
        commit_write: ll_commit_write,
        bmap: NULL
};
