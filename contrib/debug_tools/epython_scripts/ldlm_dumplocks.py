#!/usr/bin/env python

"""
Copyright 2015-2019 Cray Inc.  All Rights Reserved
Utility to list granted and waiting ldlm locks.
"""

from pykdump.API import *
import argparse
import os

import lustrelib as ll
from crashlib.input import toint

from traceback import print_exc

description = "Dumps lists of granted and waiting ldlm locks for each namespace."

''' Lock Types '''
enum_LDLM_PLAIN = 10
enum_LDLM_EXTENT = 11
enum_LDLM_FLOCK = 12
enum_LDLM_IBITS = 13

LOCKMODES = {
    0:"--",
    1:"EX",
    2:"PW",
    4:"PR",
    8:"CW",
    16:"CR",
    32:"NL",
    64:"GROUP"
}

def lockmode2str(mode):
    return LOCKMODES.get(mode, "??")

def ldlm_dump_lock(lock, pos, lstname):
    obd = None
    imp = None
    if(lock == None):
        print "   NULL LDLM lock"
        return
    print "   -- Lock: (ldlm_lock) %#x/%#x (rc: %d) (pos: %d/%s) (pid: %d)" % \
          (Addr(lock), lock.l_handle.h_cookie, lock.l_refc.counter,
          pos, lstname, lock.l_pid)
    if(lock.l_conn_export):
        obd = lock.l_conn_export.exp_obd
    if(lock.l_export and lock.l_export.exp_connection):
        print "       Node: NID %s (remote: %#x) export" % \
              (ll.nid2str(lock.l_export.exp_connection.c_peer.nid),
              lock.l_remote_handle.cookie)
    elif(obd == None):
        print "       Node: local"
    else:
        imp = obd.u.cli.cl_import
        print "       Node: NID %s (remote: %#x) import " % \
              (ll.nid2str(imp.imp_connection.c_peer.nid),
              lock.l_remote_handle.cookie)

    res = lock.l_resource
    print "       Resource: %#x [0x%x:0x%x:0x%x].%x" % \
          (Addr(res),
          res.lr_name.name[0],
          res.lr_name.name[1],
          res.lr_name.name[2],
          res.lr_name.name[3])

    print "       Req mode: %s, grant mode: %s, rc: %d, read: %d, \
          write: %d flags: %#x" % (lockmode2str(lock.l_req_mode),
          lockmode2str(lock.l_granted_mode),
          lock.l_refc.counter, lock.l_readers, lock.l_writers,
          lock.l_flags)

    lr_type = lock.l_resource.lr_type
    if(lr_type == enum_LDLM_EXTENT):
        print "       Extent: %d -> %d (req %d-%d)" % \
              (lock.l_policy_data.l_extent.start,
              lock.l_policy_data.l_extent.end,
              lock.l_req_extent.start, lock.l_req_extent.end)
    elif(lr_type == enum_LDLM_FLOCK):
        print "       Pid: %d Flock: 0x%x -> 0x%x" % \
              (lock.l_policy_data.l_flock.pid,
              lock.l_policy_data.l_flock.start,
              lock.l_policy_data.l_flock.end)
    elif(lr_type == enum_LDLM_IBITS):
        print "       Bits: %#x" % \
              (lock.l_policy_data.l_inodebits.bits)

def ldlm_dump_resource(res):
    res_lr_granted = readSU('struct list_head', Addr(res.lr_granted))
    res_lr_waiting = readSU('struct list_head', Addr(res.lr_waiting))
    print "-- Resource: (ldlm_resource) %#x [0x%x:0x%x:0x%x].%x (rc: %d)" % \
          (Addr(res), res.lr_name.name[0], res.lr_name.name[1],
           res.lr_name.name[2], res.lr_name.name[3], res.lr_refcount.counter)
    if not ll.list_empty(res_lr_granted):
        pos = 0
        print "   Granted locks: "
        tmp = res_lr_granted.next
        while(tmp != res_lr_granted):
            pos += 1
            lock = readSU('struct ldlm_lock',
                          Addr(tmp)-member_offset('struct ldlm_lock', 'l_res_link'))
            ldlm_dump_lock(lock, pos, "grnt")
            tmp = tmp.next
    if not ll.list_empty(res_lr_waiting):
        pos = 0
        print "   Waiting locks: "
        tmp = res_lr_waiting.next
        while(tmp != res_lr_waiting):
            pos += 1
            lock = readSU('struct ldlm_lock',
                          Addr(tmp)-member_offset('struct ldlm_lock', 'l_res_link'))
            ldlm_dump_lock(lock, pos, "wait")
            tmp = tmp.next

def print_namespace(ns, client_server):
    print "Namespace: (ldlm_namespace) %#x, %s\t(rc: %d, side: %s)\tpoolcnt: %d unused: %d" % \
          (Addr(ns), ll.obd2str(ns.ns_obd), ns.ns_bref.counter,
          client_server, ns.ns_pool.pl_granted.counter, ns.ns_nr_unused)

def ldlm_dump_ns_resources(ns):
    if args.nflag:
        return
    for hnode in ll.cfs_hash_get_nodes(ns.ns_rs_hash):
        offset = member_offset('struct ldlm_resource', 'lr_hash')
        res = readSU('struct ldlm_resource', Addr(hnode) - offset)
        ldlm_dump_resource(res)

def ldlm_dump_all_namespaces(ns_name, client_server):
    ns_list = readSymbol(ns_name)
    for ns in readSUListFromHead(ns_list, 'ns_list_chain', 'struct ldlm_namespace'):
        print_namespace(ns, client_server)
        ldlm_dump_ns_resources(ns)

def ldlm_dumplocks():
    if args.ns_addr:
        ns = readSU('struct ldlm_namespace', args.ns_addr)
        print_namespace(ns, "")
        ldlm_dump_ns_resources(ns)
    else:
        ldlm_dump_all_namespaces('ldlm_srv_namespace_list', "server")
        ldlm_dump_all_namespaces('ldlm_cli_active_namespace_list', "client")
        ldlm_dump_all_namespaces('ldlm_cli_inactive_namespace_list', "inactive")

if __name__ == "__main__":
    description = "Dumps lists of granted and waiting locks for each namespace. " + \
                  "Requires Lustre .ko files to be loaded (see mod command)."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-n", dest="nflag", action='store_true',
        help="Print only namespace information")
    parser.add_argument("ns_addr", nargs="?", default=[], type=toint,
        help="Print only locks under namespace at given address")
    args = parser.parse_args()

    ldlm_dumplocks()
