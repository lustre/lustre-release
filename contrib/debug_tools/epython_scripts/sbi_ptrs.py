#!/usr/bin/env python
"""
Copyright (c) 2019 Cray Inc. All Rights Reserved.
Utility to display Lustre inode related struct pointers
"""

from pykdump.API import *
import argparse
from crashlib.input import toint

description_short = "Prints Lustre structs associated with inode."

def dump_inode(inode):
     offset = member_offset('struct ll_inode_info', 'lli_vfs_inode')
     lli = readSU('struct ll_inode_info', Addr(inode) - offset)
     sb = readSU('struct super_block', inode.i_sb)
     lsi = readSU('struct lustre_sb_info', sb.s_fs_info)
     llsbi = readSU('struct ll_sb_info', lsi.lsi_llsbi)
     print "%x %x %x %x %x" % (Addr(inode), lli, sb, lsi, llsbi)

def dump_inode_list(inodes):
    print "%-16s %-16s %-16s %-16s %-16s" % ("inode", "ll_inode_info",
          "super_block", "lustre_sb_info", "ll_sb_info")
    for addr in inodes:
        dump_inode(readSU('struct inode', addr))

if __name__ == "__main__":
    description = "Prints ll_inode_info, super_block, \n" + \
            "lustre_sb_info, and ll_sb_info pointers associated \n" + \
	    "with specified inode(s) \n"

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('inode', nargs="+", type=toint,
        help="list of one or more inodes")
    args = parser.parse_args()

    dump_inode_list(args.inode)
