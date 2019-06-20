#!/usr/bin/env python

"""
Copyright 2015-2019 Cray Inc.  All Rights Reserved
Dumps the Lustre RPC queues for all ptlrpcd_XX threads.
"""

from pykdump.API import *
import sys
import argparse
import os

import lustrelib as ll
from crashlib.input import toint

from traceback import print_exc

description_short = "Displays the RPC queues of the Lustre ptlrpcd daemons"

def print_separator(count):
    s = ""
    for idx in xrange(count):
        s += "="
    print s

def print_title(title):
    if title:
        print "\n" + title
        print "%-14s %-6s %-19s %-18s %-19s %-4s %-14s %-4s %-22s %-19s" \
               % ("thread", "pid", "ptlrpc_request", "xid", "nid", "opc",
                  "phase:flags", "R:W", "sent/deadline", "ptlrpc_body")
    print_separator(148)

def enum(**enums):
    return type('Enum', (), enums)

REQ_Q = enum(rq_list=1, replay_list=2, set_chain=3, ctx_chain=4,
             unreplied_list=5, timed_list=5, exp_list=6, hist_list=7)

RQ_LIST_LNKS = {
    REQ_Q.rq_list:        ['struct ptlrpc_request', 'rq_list', 'rq_type'],
    REQ_Q.replay_list:    ['struct ptlrpc_request', 'rq_replay_list', 'rq_type'],
    REQ_Q.set_chain:      ['struct ptlrpc_cli_req', 'cr_set_chain', 'rq_cli'],
    REQ_Q.ctx_chain:      ['struct ptlrpc_cli_req', 'cr_ctx_chain', 'rq_cli'],
    REQ_Q.unreplied_list: ['struct ptlrpc_cli_req', 'cr_unreplied_list', 'rq_cli'],
    REQ_Q.timed_list:     ['struct ptlrpc_srv_req', 'sr_timed_list', 'rq_srv'],
    REQ_Q.exp_list:       ['struct ptlrpc_srv_req', 'sr_exp_list', 'rq_srv'],
    REQ_Q.hist_list:      ['struct ptlrpc_srv_req', 'sr_hist_list', 'rq_srv']
}

STRUCT_IDX = 0
MEMBER_IDX = 1
UNION_IDX = 2

def size_round(val):
    return ((val + 7) & (~0x7))

LUSTRE_MSG_MAGIC_V2 = 0x0BD00BD3

def get_ptlrpc_body(req):
    msg = req.rq_reqmsg
#    msg = req.rq_repmsg
    if not msg or msg == None:
        return None

    if msg.lm_magic != LUSTRE_MSG_MAGIC_V2:
        return None

    bufcount = msg.lm_bufcount
    if bufcount < 1:
        return None

    buflen = msg.lm_buflens[0]
    if buflen < getSizeOf('struct ptlrpc_body_v2'):
        return None

    offset = member_offset('struct lustre_msg_v2', 'lm_buflens')

    buflen_size = getSizeOf("unsigned int")
    offset += buflen_size * bufcount
    offset = size_round(offset)
    addr = Addr(msg) + offset
    if addr == 0:
        print "addr"
        return None
    return readSU('struct ptlrpc_body_v2', addr)

RQ_PHASE_NEW = 0xebc0de00
RQ_PHASE_RPC = 0xebc0de01
RQ_PHASE_BULK = 0xebc0de02
RQ_PHASE_INTERPRET = 0xebc0de03
RQ_PHASE_COMPLETE = 0xebc0de04
RQ_PHASE_UNREG_RPC =  0xebc0de05
RQ_PHASE_UNREG_BULK = 0xebc0de06
RQ_PHASE_UNDEFINED = 0xebc0de07

PHASES = {
       RQ_PHASE_NEW: "NEW",
       RQ_PHASE_RPC: "RPC",
       RQ_PHASE_BULK: "BULK",
       RQ_PHASE_INTERPRET: "NtrPrt",
       RQ_PHASE_COMPLETE: "COMP",
       RQ_PHASE_UNREG_RPC: "UNREG",
       RQ_PHASE_UNREG_BULK: "UNBULK",
       RQ_PHASE_UNDEFINED: "UNDEF"
   }

FLAG_LEGEND = "\nFlag Legend:\n\n" + \
         "I - rq_intr\tR - rq_replied\t\tE - rq_err\te - rq_net_err\tX - rq_timedout\tS - rq_resend\t\tT - rq_restart\n" + \
         "P - rq_replay\tN - rq_no_resend\tW - rq_waiting\tC - rq_wait\tH - rq_hp\tM - rq_committed\tq - rq_req_unlinked\tu - rq_reply_unlinked\n"

def get_phase_flags(req):
    phase = req.rq_phase
    phasestr = PHASES.get(phase & 0xffffffff, "?%d" % phase)
    return "%s:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % \
           (phasestr,
           "I" if req.rq_intr else "",
           "R" if req.rq_replied else "",
           "E" if req.rq_err else "",
           "e" if req.rq_net_err else "",
           "X" if req.rq_timedout else "",
           "S" if req.rq_resend else "",
           "T" if req.rq_restart else "",
           "P" if req.rq_replay else "",
           "N" if req.rq_no_resend else "",
           "W" if req.rq_waiting else "",
           "C" if req.rq_wait_ctx else "",
           "H" if req.rq_hp else "",
           "M" if req.rq_committed else "",
           "q" if req.rq_req_unlinked else "",
           "u" if req.rq_reply_unlinked else "")

LP_POISON = 0x5a5a5a5a5a5a5a5a

def print_one_request(sthread, req):
    pb = get_ptlrpc_body(req)
    status = -1
    opc = -1
    pbaddr = -1
    if pb:
        status = pb.pb_status
        opc = pb.pb_opc
        pbaddr = Addr(pb)

    imp_invalid = 1
    nid = "LNET_NID_ANY"
    obd_name = "Invalid Import"
    if req.rq_import and req.rq_import != 0xffffffffffffffff and \
       req.rq_import != LP_POISON:
        imp_invalid = req.rq_import.imp_invalid
        obd_name = ll.obd2str(req.rq_import.imp_obd)

    if not imp_invalid and req.rq_import.imp_connection:
        nid = ll.nid2str(req.rq_import.imp_connection.c_peer.nid)
    brw = "%1d:%1d" % (req.rq_bulk_read, req.rq_bulk_write)
    rq_sent_dl = "%d/%d" % (req.rq_sent, req.rq_deadline)
    print "%-14s %-6s 0x%-17x %-18d %-19s %-4d %-14s %-4s %-22s 0x%-17x" % \
            (sthread,
            status,
            Addr(req),
            req.rq_xid,
            obd_name,
            opc,
            get_phase_flags(req),
            brw,
            rq_sent_dl,
            pbaddr)

def print_request_list(sthread, lhdr, loffset):
    try:
        for reqlnk in readStructNext(lhdr, 'next'):
            if reqlnk.next == Addr(lhdr):
                break
            req = readSU('struct ptlrpc_request', reqlnk.next-loffset)
            print_one_request(sthread, req)

    except Exception, e:
        print_exc()
        return 1
    return 0

# Find offset from start of ptlrpc_request struct of link field
# Adjusts for links that are contained in embedded union
def get_linkfld_offset(lfld):
    container = RQ_LIST_LNKS[lfld][STRUCT_IDX]
    linkfld   = RQ_LIST_LNKS[lfld][MEMBER_IDX]
    req_union = RQ_LIST_LNKS[lfld][UNION_IDX]

    off1 = member_offset('struct ptlrpc_request', req_union)
    off2 = member_offset(container, linkfld)
    return off1 + off2

def foreach_ptlrpcd_ctl(callback, *args):
    pinfo_rpcds = readSymbol('ptlrpcds')
    pinfo_count = readSymbol('ptlrpcds_num')

    for idx in xrange(pinfo_count):
        ptlrpcd = pinfo_rpcds[idx]
        for jdx in xrange(ptlrpcd.pd_nthreads):
            pd = ptlrpcd.pd_threads[jdx]
            callback(pd, *args)
    pd = readSymbol('ptlrpcd_rcv')
    callback(pd, *args)

def get_daemon_listhdrs(pd, sent_rpcs, pend_rpcs):
    sent_rpcs.append([pd.pc_name, pd.pc_set.set_requests])
    pend_rpcs.append([pd.pc_name, pd.pc_set.set_new_requests])

def dump_list_of_lists(rpc_list, loffset):
    for qinfo in rpc_list:
        sthread, lhdr = qinfo
        print_request_list(sthread, lhdr, loffset)

def dump_daemon_rpclists():
    sent_rpcs = []
    pend_rpcs = []

    foreach_ptlrpcd_ctl(get_daemon_listhdrs, sent_rpcs, pend_rpcs)
    offset = get_linkfld_offset(REQ_Q.set_chain)

    print_title("Sent RPCS: ptlrpc_request_set.set_requests->")
    dump_list_of_lists(sent_rpcs, offset)

    print_title("Pending RPCS: ptlrpc_request_set.set_new_requests->")
    dump_list_of_lists(pend_rpcs, offset)
    print_title('')

def print_overview_entry(pd):
    s = "%s:" % pd.pc_name
    print "%-14s  ptlrpcd_ctl 0x%x   ptlrpc_request_set 0x%x" % \
        (s, Addr(pd), pd.pc_set)

def dump_overview():
    foreach_ptlrpcd_ctl(print_overview_entry)

def print_pcset_stats(pd):
    if pd.pc_set.set_new_count.counter != 0 or \
        pd.pc_set.set_remaining.counter != 0:
        s = "%s:" %pd.pc_name
        print "%-13s 0x%-18x %-4d %-4d %-6d" % \
            (s, Addr(pd.pc_set),
            pd.pc_set.set_refcount.counter,
            pd.pc_set.set_new_count.counter,
            pd.pc_set.set_remaining.counter)

def dump_pcsets():
    print '%-14s %-19s %-4s %-4s %-6s' % \
        ("thread", "ptlrpc_request_set", "ref", "new", "remain")
    print_separator(52)
    foreach_ptlrpcd_ctl(print_pcset_stats)

def dump_one_rpc(addr):
    print_title("Request")
    req = readSU('struct ptlrpc_request', addr)
    print_one_request('', req)

def dump_one_rpclist(addr, link_fld):
    lhdr = readSU('struct list_head', addr)
    d = vars(REQ_Q)
    loffset = get_linkfld_offset(d[link_fld])

    print_title("Request list at %s" % lhdr)
    print_request_list('', lhdr, loffset)

def dump_rpcs_cmd(args):
    if args.oflag:
        dump_overview()
        return
    if args.sflag:
        dump_pcsets()
        return
    if args.rpc_addr:
        if args.link_fld:
            dump_one_rpclist(args.rpc_addr[0], args.link_fld)
        else:
            # dump_one_rpc(args.rpc_addr[0])
            dump_one_rpc(args.rpc_addr)
        return
    dump_daemon_rpclists()

if __name__ == "__main__":
#    usage = "$(prog)s [-o] [-s] [-l link_field] [addr]\n" + \
    description = "" +\
        "Displays lists of Lustre RPC requests. If no arguments are \n" +\
        "specified, all rpcs in the sent and pending queues of the \n" +\
        "ptlrpcd daemons are printed. If an address is specified, it \n" +\
        "must be a pointer to either a ptlrpc_request or a list_head \n" +\
        "struct. If the addr is a list_head, then a link_field must \n" +\
        "also be provided. The link_field identifies the member of \n" +\
        "the ptlrpc_request struct used to link the list together."

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description, epilog=FLAG_LEGEND)
    parser.add_argument("-o", dest="oflag", action="store_true",
        help="print overview of ptlrpcd_XX threads with ptlrpcd_ctl " + \
            "structs and the associated pc_set field")
    parser.add_argument("-s", dest="sflag", action="store_true",
        help="print rpc counts per ptlrpc_request_set")
    parser.add_argument("-l", dest="link_fld", default="",
        choices=['rq_list', 'replay_list', 'set_chain', 'ctx_chain',
                 'unreplied_list', 'timed_list', 'exp_list', 'hist_list'],
        help="name of link field in ptlrpc_request for list headed by addr")
    parser.add_argument("rpc_addr", nargs="?", default=[], type=toint,
        help="address of either single ptlrpc_request or list_head; list_head requires a -l argument")
    args = parser.parse_args()

    dump_rpcs_cmd(args)
