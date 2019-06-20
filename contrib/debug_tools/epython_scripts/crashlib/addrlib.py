
"""
Set of routines for manipulating addresses.
Copyright 2014 Cray Inc.  All Rights Reserved
"""

import crashlib.cid
import crashlib.cid.machdep_table

# --------------------------------------------------------------------------

def ptov(physaddr):
    """Convert a physical address to a kernel virtual address."""
    return int(physaddr) + crashlib.cid.mdtbl.kvbase

def phys2pfn(physaddr):
    """Convert a physical address to a page offset."""
    return physaddr >> crashlib.cid.mdtbl.pageshift

def pfn2phys(pfn):
    """Convert a page offset into a physical address."""
    return pfn << crashlib.cid.mdtbl.pageshift
