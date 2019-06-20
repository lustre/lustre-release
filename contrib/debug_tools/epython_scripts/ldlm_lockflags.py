#!/usr/bin/env python

"""
Utility to print LDLM lock flags as strings
Copyright (c) 2019 Cray Inc. All Rights Reserved.
"""
from pykdump.API import *
from crashlib.input import toint
import argparse

description_short  = "Prints string identifiers for specified LDLM flags."
LDLM_FL_ALL_FLAGS_MASK = 0x00FFFFFFC28F932F

ldlm_flags_tbl = {
    0x0000000000000001:  "LOCK_CHANGED",            # bit  0
    0x0000000000000002:  "BLOCK_GRANTED",           # bit  1
    0x0000000000000004:  "BLOCK_CONV",              # bit  2
    0x0000000000000008:  "BLOCK_WAIT",              # bit  3
    0x0000000000000010:  "SPECULATIVE",             # bit  4
    0x0000000000000020:  "AST_SENT",                # bit  5
    0x0000000000000100:  "REPLAY",                  # bit  8
    0x0000000000000200:  "INTENT_ONLY",             # bit  9
    0x0000000000001000:  "HAS_INTENT",              # bit 12
    0x0000000000008000:  "FLOCK_DEADLOCK",          # bit 15
    0x0000000000010000:  "DISCARD_DATA",            # bit 16
    0x0000000000020000:  "NO_TIMEOUT",              # bit 17
    0x0000000000040000:  "BLOCK_NOWAIT",            # bit 18
    0x0000000000080000:  "TEST_LOCK",               # bit 19
    0x0000000000100000:  "MATCH_LOCK",              # bit 20
    0x0000000000800000:  "CANCEL_ON_BLOCK",         # bit 23
    0x0000000001000000:  "COS_INCOMPAT",            # bit 24
    0x0000000002000000:  "CONVERTING",              # bit 25
    0x0000000010000000:  "LOCKAHEAD_OLD_RESERVED",  # bit 28
    0x0000000020000000:  "NO_EXPANSION",            # bit 29
    0x0000000040000000:  "DENY_ON_CONTENTION",      # bit 30
    0x0000000080000000:  "AST_DISCARD_DATA",        # bit 31
    0x0000000100000000:  "FAIL_LOC",                # bit 32
    0x0000000400000000:  "CBPENDING",               # bit 34
    0x0000000800000000:  "WAIT_NOREPROC",           # bit 35
    0x0000001000000000:  "CANCEL",                  # bit 36
    0x0000002000000000:  "LOCAL_ONLY",              # bit 37
    0x0000004000000000:  "FAILED",                  # bit 38
    0x0000008000000000:  "CANCELING",               # bit 39
    0x0000010000000000:  "LOCAL",                   # bit 40
    0x0000020000000000:  "LVB_READY",               # bit 41
    0x0000040000000000:  "KMS_IGNORE",              # bit 42
    0x0000080000000000:  "CP_REQD",                 # bit 43
    0x0000100000000000:  "CLEANED",                 # bit 44
    0x0000200000000000:  "ATOMIC_CB",               # bit 45
    0x0000400000000000:  "BL_AST",                  # bit 46
    0x0000800000000000:  "BL_DONE",                 # bit 47
    0x0001000000000000:  "NO_LRU",                  # bit 48
    0x0002000000000000:  "FAIL_NOTIFIED",           # bit 49
    0x0004000000000000:  "DESTROYED",               # bit 50
    0x0008000000000000:  "SERVER_LOCK",             # bit 51
    0x0010000000000000:  "RES_LOCKED",              # bit 52
    0x0020000000000000:  "WAITED",                  # bit 53
    0x0040000000000000:  "NS_SRV",                  # bit 54
    0x0080000000000000:  "EXCL",                    # bit 55
    0x0100000000000000:  "RESENT",                  # bit 56
    0x0200000000000000:  "COS_ENABLED",             # bit 57
    0x0400000000000000:  "NDELAY"                   # bit 58
}

def print_flags(flag_dict, mask):

    flags = ""
    tmp = mask
    for key, value in flag_dict.iteritems():
            if key & mask:
                flags = flags + value + " "
                tmp &= ~key
    print "mask: 0x%x = %s" % (mask, flags)
    if tmp != 0:
        print "unknown bits set in mask: 0x%x" % tmp

if __name__ == "__main__":
    description = "Prints string identifiers for specified LDLM flags."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("bitmask", type=toint,
        help="LDLM flag bit mask to be translated")
    args = parser.parse_args()
    print_flags(ldlm_flags_tbl, args.bitmask)
