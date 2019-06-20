#!/usr/bin/env python

"""
Utility to display a Lustre cfs_hash table
Copyright (c) 2019 Cray Inc. All Rights Reserved.
"""

from pykdump.API import *
#from struct import *
import argparse
import os

import lustrelib as ll
from crashlib.input import toint

description_short = "Displays the specified Lustre hash table "

DEPTH = 3
RULER = "........................................"

hash_objects = {
    'ldlm_res_hop_object': ['struct ldlm_resource', 'lr_hash'],
    'jobid_object':        ['struct jobid_to_pid_map', 'jp_hash'],
    'lu_obj_hop_object':   ['struct lu_object_header', 'loh_hash'],
    'uuid_export_object':  ['struct obd_export', 'export_uuid_hash'],
    'nid_export_object':   ['struct obd_export', 'exp_nid_hash'],
    'nidstats_object':     ['struct nid_stat', 'nid_hash'],
    'gen_export_object':   ['struct obd_export', 'exp_gen_hash'],
    'oqi_object':          ['struct osc_quota_info', 'oqi_hash'],
    'conn_object':         ['struct ptlrpc_connection', 'c_hash']}

def get_hash_object(hs, hnode):
    s = addr2sym(hs.hs_ops.hs_object)
    if s not in hash_objects:
        return ''
    obj = hash_objects[s]
    obj_addr = Addr(hnode) -  member_offset(obj[0], obj[1])
    return "%s %x" % (obj[0], obj_addr)

def dump_hnodes(hs, hlist, hnode, depth=0, ruler=RULER):
    while(hnode != hlist & hnode):
        s = get_hash_object(hs, hnode)
        print "%*.*shlist_node 0x%x  %s" % (depth, depth, ruler, Addr(hnode), s)
        hnode = hnode.next

def dump_hlist(hs, hlist, depth=0, ruler=RULER):
    if hlist.first:
        hnode = hlist.first
        print "%*.*shlist_head 0x%x" % (depth, depth, ruler, Addr(hlist))
        dump_hnodes(hs, hlist, hnode, depth+DEPTH, ruler)

def dump_hash_bucket(hs, bd_bkt, depth=0, ruler=RULER):
    print "%*.*scfs_hash_bucket 0x%x" % (depth, depth, ruler, Addr(bd_bkt))
    for bd_offset in range(ll.CFS_HASH_BKT_NHLIST(hs)):
        hlist = ll.cfs_hash_hhead(hs, bd_bkt, bd_offset)
        if hlist:
            dump_hlist(hs, hlist, depth+DEPTH, ruler)

def dump_hash_table(hs):
    print "cfs_hash@0x%x" % Addr(hs)

    for bd_bkt in ll.cfs_hash_get_buckets(hs):
        dump_hash_bucket(hs, bd_bkt, DEPTH, RULER)

if __name__ == "__main__":
    description = "Displays the specified Lustre hash table "
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("htable", default=False, type=toint,
        help="address of a cfs_hash struct")
    args = parser.parse_args()

    hs = readSU('struct cfs_hash', args.htable)
    dump_hash_table(hs)
