#!/usr/bin/env python

"""
Utility to display Lustre cfs_hash tables
Copyright (c) 2019 Cray Inc. All Rights Reserved.
"""

from pykdump.API import *
import argparse

import lustrelib as ll

description_short = 'Displays summary of cfs_hash tables'

CFS_HASH_THETA_BITS = 10

def cfs_hash_cur_theta(hs):
    hs_cnt = readSU('atomic_t', hs.hs_count).counter
    return ((hs_cnt << CFS_HASH_THETA_BITS) >> hs.hs_cur_bits)

def cfs_hash_theta_int(theta):
    return (theta >> CFS_HASH_THETA_BITS)

def cfs_hash_theta_frac(theta):
    frac = ((theta * 1000) >> CFS_HASH_THETA_BITS) - \
           (cfs_hash_theta_int(theta) * 1000)
    return frac

def cfs_hash_format_theta(theta):
    val = str(cfs_hash_theta_int(theta)) + \
          "." + \
          str(cfs_hash_theta_frac(theta))
    return val

def print_theta(hs):
    theta = cfs_hash_cur_theta(hs)
    print "Theta: %d %s" % (theta, cfs_hash_format_theta(theta))

def print_thetas(name, hashtable):
    hs = readSU('struct cfs_hash', hashtable)
    if hs:
        print_theta(hs)

def print_separator(count):
    s = ""
    for idx in xrange(count):
        s += "="
    print s

def print_hash_labels():
    print "%-15s %-17s\t %-5s %-5s %-5s %-5s %-5s %-5s %-5s " \
          "%-5s %-5s %-5s %-5s %-11s %-11s %-11s %-5s" % \
          ("name", "cfs_hash", "cnt", "rhcnt", "xtr", "cur", "min", "max", "rhash", \
           "bkt", "nbkt", "nhlst", "flags", "theta", "minT", "maxT", "bktsz")

def print_hash_summary(name, hashtable):
    hs = readSU('struct cfs_hash', hashtable)
    if hs:
        hs_cnt = readSU('atomic_t', hs.hs_count).counter
        hs_ref = readSU('atomic_t', hs.hs_refcount).counter
        print "%-15s %-17x\t %-5d %-5d %-5d %-5d %-5d %-5d %-5d %-5d %-5d %-5d %-5x %-11s %-11s %-11s %-5d" % \
              (name, (Addr(hs)), \
               readSU('atomic_t', hs.hs_count).counter, \
               hs.hs_rehash_count, \
               hs.hs_extra_bytes, \
               hs.hs_cur_bits, \
               hs.hs_min_bits, \
               hs.hs_max_bits, \
               hs.hs_rehash_bits, \
               hs.hs_bkt_bits, \
               ll.CFS_HASH_NBKT(hs), \
               ll.CFS_HASH_BKT_NHLIST(hs), \
               hs.hs_flags, \
               cfs_hash_format_theta(cfs_hash_cur_theta(hs)), \
               cfs_hash_format_theta(hs.hs_min_theta), \
               cfs_hash_format_theta(hs.hs_max_theta), \
               ll.cfs_hash_bucket_size(hs))
    else:
        print "%-15s %-17x" % \
              (name, (Addr(hs)))

def obd_print_export_hashes(obd, exp_list, fld):
    print "\nExport list head %x %s" % (exp_list, fld)
    for exp in readSUListFromHead(exp_list, fld, 'struct obd_export'):
        print_hash_summary('exp_lock', exp.exp_lock_hash)
        print_hash_summary('exp_flock', exp.exp_flock_hash)

def obd_print_one_device_hashes(obd):
    try:
        nm = ll.obd2str(obd)
    except Exception, e:
        return 1

    print "obd_device %-17x %-22s" % (Addr(obd), ll.obd2str(obd))
    print_hash_labels()

    print_hash_summary("uuid", obd.obd_uuid_hash)
    print_hash_summary("nid", obd.obd_nid_hash)
    print_hash_summary("nid_stats", obd.obd_nid_stats_hash)

    if "clilov" in nm:
        print_hash_summary("lov_pools", obd.u.lov.lov_pools_hash_body)
    elif "clilmv" in nm:
        pass
    else:
        print_hash_summary("cl_quota0", obd.u.cli.cl_quota_hash[0])
        print_hash_summary("cl_quota1", obd.u.cli.cl_quota_hash[1])

#    obd_print_export_hashes(obd, obd.obd_exports, 'exp_obd_chain')
#    obd_print_export_hashes(obd, obd.obd_exports_timed, 'exp_obd_chain_timed')
    print ""
    return 0

def obd_devs_hash():
    devices = readSymbol('obd_devs')

    for obd in devices:
       if not obd_print_one_device_hashes(obd) == 0:
           break
    print_separator(150)

def ldlm_print_ns_hashes(ns, type):
    ns_list = readSymbol(ns)
    print "\n%s namespaces-resources" % type
    print_hash_labels()
    for ns in readSUListFromHead(ns_list, 'ns_list_chain', 'struct ldlm_namespace'):
        nm = ll.obd2str(ns.ns_obd)[0:20]
        print_hash_summary(nm, ns.ns_rs_hash)

def ldlm_namespaces_hash():
    ldlm_print_ns_hashes('ldlm_cli_active_namespace_list', "Client")
    ldlm_print_ns_hashes('ldlm_cli_inactive_namespace_list', "Inactive")
    ldlm_print_ns_hashes('ldlm_srv_namespace_list', "Server")

def lu_sites_hashes():
    lu_sites = readSymbol('lu_sites')
    print_hash_labels()
    for site in readSUListFromHead(lu_sites, 'ls_linkage', 'struct lu_site'):
        print_hash_summary("lu_site_vvp", site.ls_obj_hash)
    print ""


def global_hashes():
    print_hash_labels()
    print_hash_summary("conn_hash", readSymbol('conn_hash'))
    if symbol_exists('jobid_hash'):
        print_hash_summary("jobid_hash", readSymbol('jobid_hash'))
    if symbol_exists('cl_env_hash'):
        print_hash_summary("cl_env_hash", readSymbol('cl_env_hash'))
    print ""

if __name__ == "__main__":
    description = "Displays summary of hash tables in 'obd_devs'"
    parser = argparse.ArgumentParser(description=description)
    args = parser.parse_args()

    global_hashes()
    lu_sites_hashes()
    obd_devs_hash()
    ldlm_namespaces_hash()
