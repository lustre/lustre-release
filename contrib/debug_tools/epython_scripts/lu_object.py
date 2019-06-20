#!/usr/bin/env python

"""
Copyright (c) 2019 Cray Inc. All Rights Reserved.
Utility to display contents of a Lustre lu_object
"""

from pykdump.API import *
from struct import *
import argparse
import os

import lustrelib as ll
from crashlib.input import toint

description_short = "Prints contents of an lu_object"

LOHA_EXISTS = 1 << 0

LOV_MAGIC = 0x0BD10BD0
LOV_MAGIC_V3 = 0x0BD30BD0

DEPTH = 3
RULER = "........................................"

FID_SEQ_OST_MDT0 = 0
FID_SEQ_LOV_DEFAULT = 0xffffffffffffffff
FID_SEQ_IDIF = 0x100000000
FID_SEQ_IDIF_MAX = 0x1ffffffff
IDIF_OID_MAX_BITS = 48
IDIF_OID_MASK = ((1 << IDIF_OID_MAX_BITS) -1)

def lov_print_empty(obj, depth=0, ruler=RULER):
    print "empty %d" % obj.lo_layout_invalid

def lov_print_raid0(obj, depth=0, ruler=RULER):
    r0 = None
    lsm = obj.lo_lsm
    try:
        magic = lsm.lsm_magic
        stripes = lsm.lsm_stripe_count
        layout_gen = lsm.lsm_layout_gen
	pattern = lsm.lsm_pattern
    except Exception, e:
        magic = lsm.lsm_wire.lw_magic
        stripes = lsm.lsm_wire.lw_stripe_count
        layout_gen = lsm.lsm_wire.lw_layout_gen
	pattern = lsm.lsm_wire.lw_pattern
    if magic==LOV_MAGIC or magic==LOV_MAGIC_V3:
        r0 = obj.u.raid0
    lli = readU32(Addr(obj) + member_offset('struct lov_object', 'lo_layout_invalid'))
    invalid = "invalid" if lli else "valid"
    if r0 and r0.lo_nr:
        print "%*.*sstripes: %d, %s, lsm[0x%x 0x%X %d %d %d %d]:" % \
             (depth, depth, ruler,
             r0.lo_nr, invalid, Addr(lsm), magic,
             lsm.lsm_refc.counter, stripes, layout_gen, pattern)
        for i in range(r0.lo_nr):
            los = r0.lo_sub[i]
            if los:
                sub = los.lso_cl.co_lu
                lovsub_object_print(sub, depth+DEPTH, ruler)
            else:
                print "sub %d absent" % i

def lov_print_released(obj, depth=0, ruler=RULER):
    lsm = obj.lo_lsm
    magic = lsm.lsm_magic
    entries = lsm.lsm_entry_count
    layout_gen = lsm.lsm_layout_gen
    lli = readU32(Addr(obj) + member_offset('struct lov_object', 'lo_layout_invalid'))
    invalid = "invalid" if lli else "valid"
    if magic==LOV_MAGIC or magic==LOV_MAGIC_V3:
        print "%*.*sreleased: %s, lov_stripe_md: 0x%x [0x%X %d %u %u]:" % \
             (depth, depth, ruler,
             invalid, Addr(lsm), magic, lsm.lsm_refc.counter,
             entries, layout_gen)

LOV_PRINT_TYPE = {
                 0:lov_print_empty,
                 1:lov_print_raid0,
                 2:lov_print_released}

def vvp_object_print(o, depth=0, ruler=RULER):
    obj = readSU('struct vvp_object', Addr(o) - member_offset('struct vvp_object', 'vob_cl.co_lu'))
    print "%*.*s(trans:%s mmap:%d) inode: 0x%x " % \
         (depth, depth, ruler,
         obj.vob_transient_pages.counter,
         obj.vob_mmap_cnt.counter,
         Addr(obj.vob_inode))

def lod_object_print(o, depth=0, ruler=RULER):
    obj = readSU('struct lod_object', Addr(o) - member_offset('struct lod_object', 'ldo_obj.do_lu'))
    print "%*.*slod_object@0x%x" % (depth, depth, ruler, Addr(obj))

def lov_object_print(o, depth=0, ruler=RULER):
    obj = readSU('struct lov_object', Addr(o) - member_offset('struct lov_object', 'lo_cl.co_lu'))
    type = obj.lo_type
    LOV_PRINT_TYPE[type](obj, depth, ruler)

def lovsub_object_print(o, depth=0, ruler=RULER):
    obj = readSU('struct lovsub_object', Addr(o) - member_offset('struct lovsub_object', 'lso_cl.co_lu'))
    print "%*.*slso_index: %d" % (depth, depth, ruler, obj.lso_index)

def mdd_object_print(o, depth=0, ruler=RULER):
    obj = readSU('struct mdd_object', Addr(o) - member_offset('struct mdd_object', 'mod_obj.mo_lu'))
    print "%*.*smdd_object@0x%x(open_count=%d, valid=%x, cltime=%u, flags=%x)" % \
         (depth, depth, ruler, Addr(obj), obj.mod_count, obj.mod_valid,
         obj.mod_cltime, obj.mod_flags)

def mdt_object_print(o, depth=0, ruler=RULER):
    obj = readSU('struct mdt_object', Addr(o) - member_offset('struct mdt_object', 'mot_obj'))
    print "%*.*smdt_object@0x%x(ioepoch=%u, flags=%x, epochcount=%d, writecount-%d" % \
         (depth, depth, ruler, Addr(obj), obj.mot_ioepoch, obj.mot_flags,
         obj.mot_ioepoch_count, obj.mot_writecount)

def mgs_object_print(o, depth=0, ruler=RULER):
    obj = readSU('struct mgs_object', Addr(o) - member_offset('struct mgs_object', 'mgo_obj.do_lu'))
    print "%*.*smgs_object@0x%x" % (depth, depth, ruler, Addr(obj))

def echo_object_print(o, depth=0, ruler=RULER):
    clo = readSU('struct cl_object', Addr(o) - member_offset('struct cl_object', 'co_lu'))
    obj = readSU('struct echo_object', Addr(clo) - member_offset('struct echo_object', 'eo_cl'))
    print "%*.*sechocl_object@0x%x" % (depth, depth, ruler, Addr(obj))

def ofd_object_print(o, depth=0, ruler=RULER):
    print "%*.*sofd_object@0x%x" % (depth, depth, ruler, Addr(o))

def osc_object_print(o, depth=0, ruler=RULER):
    obj = readSU('struct osc_object', Addr(o) - member_offset('struct osc_object', 'oo_cl.co_lu'))
    oinfo = obj.oo_oinfo
    ar = oinfo.loi_ar
    ostid = oinfo.loi_oi
    ostid_seq = 0
    ostid_id = 0
    if ostid.oi.oi_seq == FID_SEQ_OST_MDT0:
        ostid_seq = FID_SEQ_OST_MDT0
        ostid_id = ostid.oi.oi_id & IDIF_OID_MASK
    elif ostid.oi.oi_seq == FID_SEQ_LOV_DEFAULT:
        ostid_seq = FID_SEQ_LOV_DEFAULT
        ostid_id = ostid.oi.oi_id
    elif ostid.oi_fid.f_seq >= FID_SEQ_IDIF and \
        ostid.oi_fid.f_seq <= FID_SEQ_IDIF_MAX:
        ostid_seq = FID_SEQ_OST_MDT0
        ostid_id = ((0 << 48) | (ostid.oi_fid.f_seq & 0xffff << 32) | (ostid.oi_fid.f_oid))
    else:
        ostid_seq = ostid.oi_fid.f_seq
        ostid_id = ostid.oi_fid.f_oid
    print "%*.*sid: 0x%x:%u idx: %d gen: %d kms_valid: %u kms: %u rc: %d force_sync: %d min_xid: %u" % \
         (depth, depth, ruler, ostid_seq, ostid_id,
         oinfo.loi_ost_idx, oinfo.loi_ost_gen, oinfo.loi_kms_valid,
         oinfo.loi_kms, ar.ar_rc, ar.ar_force_sync, ar.ar_min_xid)

def osd_object_print(o, depth=0, ruler=RULER):
    obj = readSU('struct osd_object', Addr(o) - member_offset('struct osd_object', 'oo_dt.do_lu'))
    print "%*.*sosd_object@0x%x" % (depth, depth, ruler, Addr(obj))

def osp_object_print(o, depth=0, ruler=RULER):
    obj = readSU('struct osp_object', Addr(o) - member_offset('struct osp_object', 'opo_obj.do_lu'))
    print "%*.*sosp_object@0x%x" % (depth, depth, ruler, Addr(o))

OBJ_PRINT = {
            "vvp":vvp_object_print,
            "lod":lod_object_print,
            "lov":lov_object_print,
            "lovsub":lovsub_object_print,
            "mdd":mdd_object_print,
            "mdt":mdt_object_print,
            "mgs":mgs_object_print,
            "echo":echo_object_print,
            "ofd":ofd_object_print,
            "osc":osc_object_print,
            "osd":osd_object_print,
            "osp":osp_object_print}

def print_object_from_name(name, obj, depth=0, ruler=RULER):
    if OBJ_PRINT[name]:
        OBJ_PRINT[name](obj, depth, ruler)

def print_object(pos, depth=0, ruler=RULER):
    print "%*.*s%s@0x%x" % (depth, depth, ruler, pos.lo_dev.ld_type.ldt_name, Addr(pos))
    if (pos.lo_ops.loo_object_print):
        print_object_from_name(pos.lo_dev.ld_type.ldt_name, pos, depth+DEPTH, ruler)

def print_object_from_header(loh, depth=0, ruler=RULER):
    head = loh.loh_layers
    empty = "" if (loh.loh_lru.next == loh.loh_lru) else " lru"
    exists = " exist" if loh.loh_attr & LOHA_EXISTS else ""
    print "%*.*slu_object_header@0x%x[fl:0x%x, rc:%d, [0x%x:0x%x:0x%x]%s%s] {" % \
         (depth, depth, ruler,
         Addr(loh),
         loh.loh_flags,
         loh.loh_ref.counter,
         loh.loh_fid.f_seq,
         loh.loh_fid.f_oid,
         loh.loh_fid.f_ver,
         empty,
         exists)
    for obj in readSUListFromHead(head, 'lo_linkage', 'struct lu_object'):
        print_object(obj, depth+DEPTH, ruler)
    print "%*.*s} header@0x%x\n" % (depth, depth, ruler, Addr(loh))

if __name__ == "__main__":
    description = "Prints contents of an lu_object"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("lu_object_header", default=False, type=toint,
        help="address of an lu_object_header")

    args = parser.parse_args()
    loh = readSU('struct lu_object_header', args.lu_object_header)
    print_object_from_header(loh)
