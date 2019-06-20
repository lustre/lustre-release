#!/usr/bin/env python
from pykdump.API import *

"""
Copyright (c) 2015-2019 Cray Inc. All Rights Reserved.
Library of helper functions for Lustre scripts
"""
# hide this file from the output of 'epython scripts'.
interactive = False

"""Lustre Hash Table Utilities"""

CFS_HASH_ADD_TAIL = 1 << 4
CFS_HASH_DEPTH = 1 << 12
CFS_HASH_TYPE_MASK = CFS_HASH_ADD_TAIL | CFS_HASH_DEPTH

HH = 0
HD = CFS_HASH_DEPTH
DH = CFS_HASH_ADD_TAIL
DD = CFS_HASH_DEPTH | CFS_HASH_ADD_TAIL

def hs_get_type(hsh):
    return hsh.hs_flags & CFS_HASH_TYPE_MASK

def enum(**enums):
    return type('Enum', (), enums)

HS_INFO_FLDS = enum(dtfld=0, hdfld=1,)

# The type to struct changes and jobid_hash addition were released
# in the same version, so use existence of jobid_hash as a substitute
# for cfs_hash type changes.
if symbol_exists('jobid_hash'):    # 2.11 and later
    HS_INFO = {
        HH: ['struct cfs_hash_head', 'hh_head'],
        HD: ['struct cfs_hash_head_dep', 'hd_head'],
        DH: ['struct cfs_hash_dhead', 'dh_head'],
        DD: ['struct cfs_hash_dhead_dep', 'dd_head'],
    }
else:
    HS_INFO = {
        HH: ['cfs_hash_head_t', 'hh_head'],
        HD: ['cfs_hash_head_dep_t', 'hd_head'],
        DH: ['cfs_hash_dhead_t', 'dh_head'],
        DD: ['cfs_hash_dhead_dep_t', 'dd_head'],
    }

def CFS_HASH_NBKT(hsh):
    return (1 << (hsh.hs_cur_bits - hsh.hs_bkt_bits))

def CFS_HASH_BKT_NHLIST(hsh):
    return (1 << (hsh.hs_bkt_bits))

def cfs_hash_head_size(hsh):
    size = getSizeOf(HS_INFO[hs_get_type(hsh)][HS_INFO_FLDS.dtfld])
    return size

def cfs_hash_bucket_size(hsh):
    size = member_offset('struct cfs_hash_bucket', 'hsb_head')
    size += cfs_hash_head_size(hsh) * CFS_HASH_BKT_NHLIST(hsh) + \
            hsh.hs_extra_bytes
    return size

def cfs_hash_hhead(hsh, bd_bkt, bd_offset):
    info = HS_INFO[hs_get_type(hsh)]
    bkt = Addr(bd_bkt) + member_offset('struct cfs_hash_bucket', 'hsb_head')
    head = readSU(info[HS_INFO_FLDS.dtfld], bkt)
    offset = member_offset(info[HS_INFO_FLDS.dtfld], info[HS_INFO_FLDS.hdfld])
    return readSU('struct hlist_head', (Addr(head[bd_offset]) + offset))

def cfs_hash_get_buckets(hsh):
    hbuckets = []
    for idx in range(CFS_HASH_NBKT(hsh)):
        if hsh.hs_buckets[idx]:
            hbuckets.append(hsh.hs_buckets[idx])
    return hbuckets

def cfs_hash_get_hlist_nodes(hsh, bd_bkt, bd_offset):
    hlist = readSU('struct hlist_head', cfs_hash_hhead(hsh, bd_bkt, bd_offset))
    hnodes = []
    hnode = hlist.first
    while (hnode and hnode != hlist):
        hnodes.append(hnode)
        hnode = hnode.next
    return hnodes

def cfs_hash_get_nodes(hsh):
    hs_nodes = []
    for bd_bkt in cfs_hash_get_buckets(hsh):
        for bd_offset in range(CFS_HASH_BKT_NHLIST(hsh)):
            for hnode in cfs_hash_get_hlist_nodes(hsh, bd_bkt, bd_offset):
                hs_nodes.append(hnode)
    return hs_nodes

"""nid"""

def LNET_NIDADDR(nid):
    return (nid & 0xffffffff)

def LNET_NIDNET(nid):
    return ((nid >> 32) & 0xffffffff)

def LNET_NETTYP(net):
    return ((net >> 16) & 0xffff)

def LNET_NETNUM(net):
    return ((net) & 0xffff)

LNET_NID_ANY = 0xffffffffffffffff
LNET_NIDSTR_SIZE = 32

O2IBLND = 5
PTLLND = 4
GNILND = 13

LP_POISON = 0x5a5a5a5a5a5a5a5a

def nid2str(nid):
    if nid == LNET_NID_ANY:
        return 'LNET_NID_ANY'
    addr = LNET_NIDADDR(nid)
    net = LNET_NIDNET(nid)
    lnd = LNET_NETTYP(net)
    nnum = LNET_NETNUM(net)
    s = ""
    if lnd == O2IBLND:
        s = "%d.%d.%d.%d@o2ib" % \
            ((addr >> 24) & 0xff, (addr >> 16) & 0xff,
            (addr >> 8) & 0xff, addr & 0xff)
    elif lnd == PTLLND:
        s = "%d@ptl" % addr
    elif lnd == GNILND:
        s = "%d@gni" % addr
    else:
        nnum = 0
    if nnum != 0:
        s = "%s%d" % (s, nnum)
    return s

def obd2nidstr(obd):
    obd_import = readSU('struct obd_import', obd.u.cli.cl_import)
    nid = LNET_NID_ANY
    imp_invalid = 1
    if obd_import and obd_import != 0xffffffffffffffff and \
       obd_import != LP_POISON:
        imp_invalid = obd_import.imp_invalid

    if not imp_invalid and obd_import.imp_connection:
        if Addr(obd_import.imp_obd) == Addr(obd):
            nid = obd_import.imp_connection.c_peer.nid
    return nid2str(nid)

"""Miscellaneous"""

def obd2str(obd, partitions=2):
    name = obd.obd_name.split('-', partitions)[:partitions]
    return '-'.join(name)

def list_empty(head):
    return head.next == head

"""Red-Black"""

def rb_first(root):
    n = root.rb_node
    if not n:
        return None
    while(n.rb_left):
        n = n.rb_left
    return n

def rb_last(root):
    n = root.rb_node
    if not n:
        return None
    while(n.rb_right):
        n = n.rb_right
    return n

def rb_parent_color(node):
    return readU64(Addr(node))

def rb_parent(node):
    addr = rb_parent_color(node) & ~3
    return readSU('struct rb_node', addr)

#The color of the rb_node; 0 denotes red, 1 denotes black
def rb_color(node):
    return rb_parent_color(node) & 1

def rb_next(node):
    if rb_parent(node) == node:
        return None
    #right child exists
    if node.rb_right:
        node = node.rb_right
        while(node.rb_left):
            node = node.rb_left
        return node
    #no right child
    parent = rb_parent(node)
    while(parent and node == parent.rb_right):
        node = parent
        parent = rb_parent(node)
    return parent

def rb_prev(node):
    if rb_parent(node) == node:
        return None
    #left child exists
    if node.rb_left:
        node = node.rb_left
        while(node.rb_right):
            node = node.rb_right
        return node
    #no left child
    parent = rb_parent(node)
    while(parent.rb_left and node == parent.rb_left):
        node = parent
        parent = rb_parent(node)
    return parent

"""LNET Globals"""
the_lnet = readSymbol('the_lnet')

tmpsiz = 256

LNET_CPT_BITS = the_lnet.ln_cpt_bits
LNET_PROC_CPT_BITS = LNET_CPT_BITS + 1
LNET_LOFFT_BITS = getSizeOf('loff_t') * 8
LNET_PROC_VER_BITS = max((min(LNET_LOFFT_BITS, 64) / 4), 8)
LNET_PROC_HASH_BITS = 9
LNET_PROC_HOFF_BITS = LNET_LOFFT_BITS - LNET_PROC_CPT_BITS - LNET_PROC_VER_BITS - LNET_PROC_HASH_BITS -1
LNET_PROC_HPOS_BITS = LNET_PROC_HASH_BITS + LNET_PROC_HOFF_BITS
LNET_PROC_VPOS_BITS = LNET_PROC_HPOS_BITS + LNET_PROC_VER_BITS

LNET_PROC_CPT_MASK = (1 << LNET_PROC_CPT_BITS) - 1
LNET_PROC_VER_MASK = (1 << LNET_PROC_VER_BITS) - 1
LNET_PROC_HASH_MASK = (1 << LNET_PROC_HASH_BITS) - 1
LNET_PROC_HOFF_MASK = (1 << LNET_PROC_HASH_BITS) - 1

LNET_PING_FEAT_NI_STATUS = 1 << 1

HZ = sys_info.HZ
