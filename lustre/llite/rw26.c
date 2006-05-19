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

#include <lustre_mdc.h>
#include <lustre_lite.h>
#include "llite_internal.h"
#include <linux/lustre_compat25.h>

static int ll_writepage_26(struct page *page, struct writeback_control *wbc)
{
        return ll_writepage(page);
}

/* It is safe to not check anything in invalidatepage/releasepage below
   because they are run with page locked and all our io is happening with
   locked page too */
static int ll_invalidatepage(struct page *page, unsigned long offset)
{
        if (offset)
                return 0;
        if (PagePrivate(page))
                ll_removepage(page);
        return 1;
}

static int ll_releasepage(struct page *page, gfp_t gfp_mask)
{
        if (PagePrivate(page))
                ll_removepage(page);
        return 1;
}

struct address_space_operations ll_aops = {
        .readpage       = ll_readpage,
//        .readpages      = ll_readpages,
//        .direct_IO      = ll_direct_IO_26,
        .writepage      = ll_writepage_26,
        .writepages     = generic_writepages,
        .set_page_dirty = __set_page_dirty_nobuffers,
        .sync_page      = NULL,
        .prepare_write  = ll_prepare_write,
        .commit_write   = ll_commit_write,
        .invalidatepage = ll_invalidatepage,
        .releasepage    = ll_releasepage,
        .bmap           = NULL
};
