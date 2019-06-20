#!/usr/bin/env python

"""
Utility to print Lustre libcfs_debug flags
Copyright (c) 2019 Cray Inc. All Rights Reserved.
"""

from pykdump.API import *
from crashlib.input import toint
import argparse

description_short = "Prints Lustre libcfs_debug flags as strings"

debug_flags_tbl = {
    0x00000001: 'trace',      #define D_TRACE
    0x00000002: 'inode',      #define D_INODE
    0x00000004: 'super',      #define D_SUPER
    0x00000008: 'ext2',       #define D_EXT2
    0x00000010: 'malloc',     #define D_MALLOC
    0x00000020: 'cache',      #define D_CACHE
    0x00000040: 'info',       #define D_INFO
    0x00000080: 'ioctl',      #define D_IOCTL
    0x00000100: 'neterror',   #define D_NETERROR
    0x00000200: 'net',        #define D_NET
    0x00000400: 'warning',    #define D_WARNING
    0x00000800: 'buffs',      #define D_BUFFS
    0x00001000: 'other',      #define D_OTHER
    0x00002000: 'dentry',     #define D_DENTRY
    0x00004000: 'nettrace',   #define D_NETTRACE
    0x00008000: 'page',       #define D_PAGE
    0x00010000: 'dlmtrace',   #define D_DLMTRACE
    0x00020000: 'error',      #define D_ERROR
    0x00040000: 'emerg',      #define D_EMERG
    0x00080000: 'ha',         #define D_HA
    0x00100000: 'rpctrace',   #define D_RPCTRACE
    0x00200000: 'vfstrace',   #define D_VFSTRACE
    0x00400000: 'reada',      #define D_READA
    0x00800000: 'mmap',       #define D_MMAP
    0x01000000: 'config',     #define D_CONFIG
    0x02000000: 'console',    #define D_CONSOLE
    0x04000000: 'quota',      #define D_QUOTA
    0x08000000: 'sec',        #define D_SEC
    0x10000000: 'lfsck',      #define D_LFSCK
    0x20000000: 'hsm',        #define D_HSM
    0x40000000: 'snapshot',   #define D_SNAPSHOT
    0x80000000: 'layout'      #define D_LAYOUT
}

def print_flags(flag_tbl, mask):
    flags = ""
    tmp = mask
    for key, value in flag_tbl.iteritems():
            if key & mask:
               flags = flags + value + " "
               tmp &= ~key
    print "mask: 0x%x = %s" % (mask, flags)
    if tmp != 0:
        print "unknown bits set in mask: 0x%x" % tmp

def dump_debug_flags(bitmask):
    print bitmask
    if not bitmask:
        bitmask = readSymbol('libcfs_debug')
    print_flags(debug_flags_tbl, bitmask)

if __name__ == "__main__":
    description = "Prints libcfs_debug flags as strings"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("bitmask", nargs="?", type=toint, default=[],
        help="debug bit mask to be translated; default is current libcfs_debug value")
    args = parser.parse_args()
    dump_debug_flags(args.bitmask)
