/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite I/O page cache routines for the 2.5/2.6 kernel version
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

/* called as the osc engine completes an rpc that included our ocp.  
 * the ocp itself holds a reference to the page and will drop it when
 * the page is removed from the page cache.  our job is simply to
 * transfer rc into the page and unlock it */
void ll_complete_writepage_26(struct obd_client_page *ocp, int rc)
{
        struct page *page = ocp->ocp_page;

        LASSERT(page->private == (unsigned long)ocp);
        LASSERT(PageLocked(page));

        if (rc != 0) {
                CERROR("writeback error on page %p index %ld: %d\n", page,
                       page->index, rc);
                SetPageError(page);
        }
        ocp->ocp_flags &= ~OCP_IO_READY;

        /* let everyone get at this page again.. I wonder if this ordering
         * is corect */
        unlock_page(page);
        end_page_writeback(page);

        page_cache_release(page);
}

static int ll_writepage_26(struct page *page, struct writeback_control *wbc)
{
        struct obd_client_page *ocp;
        ENTRY;

        LASSERT(!PageDirty(page));
        LASSERT(PageLocked(page));
        LASSERT(page->private != 0);

        ocp = (struct obd_client_page *)page->private;
        ocp->ocp_flags |= OCP_IO_READY;

        page_cache_get(page);

        /* filemap_fdatawait() makes me think we need to set PageWriteback
         * on pages that are in flight.  But our ocp mechanics doesn't
         * really expect a page to be on both the osc lru and in flight.
         * so for now, we don't unlock the page.. dirtiers whill wait
         * for io to complete */
        SetPageWriteback(page);

        /* sadly, not all callers who writepage eventually call sync_page
         * (ahem, kswapd) so we need to raise this page's priority 
         * immediately */
        RETURN(ll_sync_page(page));
}

struct address_space_operations ll_aops = {
        readpage: ll_readpage,
//        readpages: ll_readpages,
//        direct_IO: ll_direct_IO_26,
        writepage: ll_writepage_26,
        writepages: generic_writepages,
        set_page_dirty: __set_page_dirty_nobuffers,
        sync_page: block_sync_page,
        prepare_write: ll_prepare_write,
        commit_write: ll_commit_write,
        bmap: NULL
};
