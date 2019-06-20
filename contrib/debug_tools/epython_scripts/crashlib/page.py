"""
Constants and routines for manipulating kernel page struct.
Copyright 2014-2017 Cray Inc.  All Rights Reserved
"""

from pykdump.API import *

import crashlib.cid
import crashlib.cid.machdep_table
import crashlib.cid.page_flags
import crashlib.cid.phys_mem_map
import crashlib.memarray

# --------------------------------------------------------------------------

page_struct_size = getSizeOf('struct page')

# --------------------------------------------------------------------------

# Create a function for determining whether a page is controlled by the
# buddy allocator.  Note that earlier kernels (< 3.0) have a page flag, while
# later kernels use the _mapcount field.

if hasattr(crashlib.cid.pgflags, 'PG_buddy'):
    def is_buddy_page(page):
        return page.flags & crashlib.cid.pgflags.PG_buddy.mask;
else:
    def is_buddy_page(page):
        # Early implementations used -2, later use -128
        return page._mapcount.counter == -128 or page._mapcount.counter == -2

if hasattr(crashlib.cid.pgflags, 'PG_compound'):
    def is_compound_page_head(page):
        return (page.flags & (crashlib.cid.pgflags.PG_reclaim.mask |
                              crashlib.cid.pgflags.PG_compound.mask)
               ) == crashlib.cid.pgflags.PG_compound

    def is_compound_page_tail(page):
        return (page.flags & (crashlib.cid.pgflags.PG_reclaim.mask |
                              crashlib.cid.pgflags.PG_compound.mask)
               ) == (crashlib.cid.pgflags.PG_reclaim.mask |
                     crashlib.cid.pgflags.PG_compound.mask)

    def is_compound_page(page):
        return page.flags & crashlib.cid.pgflags.PG_compound.mask

elif hasattr(crashlib.cid.pgflags, 'PG_tail'):
    # PG_head and PG_tail defined
    def is_compound_page_head(page):
        return page.flags & (crashlib.cid.pgflags.PG_head.mask)

    def is_compound_page_tail(page):
        return page.flags & (crashlib.cid.pgflags.PG_tail.mask)

    def is_compound_page(page):
        return is_compound_page_head(page) or is_compound_page_tail(page)

else:
    # Only PG_head is defined
    def is_compound_page_head(page):
        return page.flags & (crashlib.cid.pgflags.PG_head.mask)

    def is_compound_page_tail(page):
        return page.compound_head & 1

    def is_compound_page(page):
        return is_compound_page_head(page) or is_compound_page_tail(page)

# --------------------------------------------------------------------------

# Find the page order of a buddy page

def buddy_order(page):
    """Retrieve the order of a page in the buddy allocator"""
    return page.private

# --------------------------------------------------------------------------

# Create a function to determine the page order of a compound page

if member_offset('struct page', 'compound_order') > -1:
    def compound_order(page):
        """Retrieve the page order for a compound page."""
        # A compound page is a series of contiguous pages, thus there are
        # at least two page structs.  The second page struct (first tail page)
        # contains the page order; the head page uses the space for a
        # different purpose.
        return page[1].compound_order

else:
    def compound_order(page):
        """Retrieve the page order for a compound page."""
        # A compound page is a series of contiguous pages, thus there are
        # at least two page structs.  The second page struct (first tail page)
        # contains the page order stored in the lru.prev field; the head page
        # uses the space for a different purpose.
        return page[1].lru.prev

# --------------------------------------------------------------------------

def pfn(page):
    """Returns the pfn for the supplied page struct or page struct address."""
    vmemmap_vaddr = crashlib.cid.mdtbl.vmemmap_vaddr
    return (page - vmemmap_vaddr) / page_struct_size

# --------------------------------------------------------------------------

def page_list():
    """Return a list-like class of page structs indexed by pfn.

    This implementation assumes the kernel is configured with a virtually
    contiguous mem_map.
    """
    # If the kernel doesn't have a virtually contiguous mem_map, this could
    # be changed to return a chained list of MemCArray objects.

    PAGE_SHIFT = crashlib.cid.mdtbl.pageshift
    pfn_start  = crashlib.cid.physmap[0].start >> PAGE_SHIFT
    pfn_end    = crashlib.cid.physmap[-1].end >> PAGE_SHIFT

    # Find page map and create an array of page_struct
    vmemmap_addr = crashlib.cid.mdtbl.vmemmap_vaddr

    return crashlib.memarray.MemCArray(vmemmap_addr,
                                        lambda a:readSU('struct page',a),
                                        getSizeOf('struct page'),
                                        pfn_end-pfn_start)
