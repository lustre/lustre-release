#!/usr/bin/env python
"""
Copyright 2015-2019 Cray Inc.  All Rights Reserved
Utility to dump the Lustre dk logs.
Based on dump_cfs_trace_data.py
"""

import sys
import crash
import argparse
from time import localtime
from operator import itemgetter
from pykdump.API import getSizeOf, readSU, readmem, readSUListFromHead, readSymbol, sys_info
from crashlib import page, addrlib
import os

description_short = 'Dump and sort the Lustre dk logs.'

def do_shell_cmd(cmd):
    return os.popen(cmd).read()

# ---------------------------------------------------------------------------
# pfn: 2582e8c, physaddr: 2582e8c000, vaddr: ffff002582e8c000
def dump_dk_line(tmpfd, options, pfn, used):
    """Dump the cfs debug messages in the dk format."""
    physaddr = addrlib.pfn2phys(pfn)
    vaddr = addrlib.ptov(physaddr)
    hdr_size = getSizeOf("struct ptldebug_header")

    while (used):
        hdr = readSU('struct ptldebug_header', vaddr)
        laddr = vaddr + hdr_size
        try:
            line = readmem(laddr, hdr.ph_len - hdr_size)
	except:
            print "Skipping pfn: %x, physaddr: %x, vaddr: %x, laddr: %x" % \
                (pfn, physaddr, vaddr, laddr)
            return

        (filename,function,text) = line.split('\0')
        text = text.rstrip()

        used -= hdr.ph_len
        vaddr += hdr.ph_len

        type = hdr.ph_type
        prefix = "%08x:%08x:%u.%u%s:%u.%u" % \
            (hdr.ph_subsys, hdr.ph_mask, hdr.ph_cpu_id, hdr.ph_type,
            "F" if (hdr.ph_flags & 1) else "", hdr.ph_sec, hdr.ph_usec)

        buf = "%s:%06u:%u:%u:(%s:%d:%s()) %s" % \
            (prefix, hdr.ph_stack, hdr.ph_pid, hdr.ph_extern_pid, filename,
            hdr.ph_line_num, function, text)

        tmpfd.write(buf + '\n')

# ---------------------------------------------------------------------------
def walk_pages(tmpfd, options, cfs_page_head, trace_page_struct):

    cfs_pages = readSUListFromHead(cfs_page_head, 'linkage',
                                   trace_page_struct,
                                   maxel=100000, inchead=False)

    for p in cfs_pages:
        dump_dk_line(tmpfd, options, page.pfn(p.page), p.used)

# ---------------------------------------------------------------------------
def walk_array(options):
    """Walk the cfs_trace_data array of array pointers."""

    fname = do_shell_cmd('mktemp .dklogXXXX').rstrip()
    tmpfd = file(fname, 'w')

    try:
        cfs_trace_data = readSymbol('cfs_trace_data')
        trace_page_struct = 'struct cfs_trace_page'
    except TypeError:
        try:
            cfs_trace_data = readSymbol('trace_data')
            trace_page_struct = 'struct trace_page'
        except:
            print "Ensure you have loaded the Lustre modules"
            return 1

    for cfstd_array in cfs_trace_data:
        if not cfstd_array: continue

        for i in xrange(sys_info.CPUS):
            u = cfstd_array[i]
            walk_pages(tmpfd, options, u.tcd.tcd_pages, trace_page_struct)
            walk_pages(tmpfd, options, u.tcd.tcd_stock_pages, trace_page_struct)

    tmpfd.close()
    print do_shell_cmd('sort -n -s -t: -k4,4 ' + fname)
    print do_shell_cmd('rm ' + fname)

# ---------------------------------------------------------------------------
def dump_dk_log():
    parser = argparse.ArgumentParser(
        description= "Dump and sort the Lustre dk logs.",
        epilog= "NOTE: the Lustre kernel modules must be loaded.")
    args = parser.parse_args()
    return walk_array(args)

if __name__ == '__main__':
    dump_dk_log()
