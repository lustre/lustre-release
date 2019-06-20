#!/usr/bin/env python

"""
Copyright (c) 2015-2019 Cray Inc. All Rights Reserved.
Utility to display obd_devices
"""

from pykdump.API import *
import argparse

from crashlib.input import toint
import lustrelib as ll
import rpc_stats as rs

description_short = "Displays the contents of global 'obd_devs'"

SEP_SIZE = 152
def print_separator(count):
    s=""
    for idx in xrange(count):
        s += "="
    print s

def print_header():
    print "%-19s %-22s \t%-22s %-19s %-19s %-12s %-10s %-7s %-10s" % \
         ("obd_device",
          "obd_name",
          "ip_address",
          "client_obd",
          "obd_import",
          "imp_state",
          "ish_time",
          "index",
          "conn_cnt")
    print_separator(SEP_SIZE)

IMP_STATE = {
        1:  "CLOSED",
        2:  "NEW",
        3:  "DISCON",
        4:  "CONNECTING",
        5:  "REPLAY",
        6:  "REPLAY_LOCKS",
        7:  "REPLAY_WAIT",
        8:  "RECOVER",
        9:  "FULL",
       10:  "EVICTED",
       11:  "IDLE"
}


def print_one_device(obd, stats_flag):
    try:
        nid = ll.obd2nidstr(obd)
    except Exception, e:
        try:
            print "0x%-17x %-22s" % (Addr(obd), ll.obd2str(obd))
        except Exception, e:
            return 1
        return 0

    impstate = "--"
    ish_time = 0
    index=-1
    connect_cnt = 0
    inflight=0
    if obd.u.cli.cl_import:
          impstate=IMP_STATE.get(obd.u.cli.cl_import.imp_state)
          index=obd.u.cli.cl_import.imp_state_hist_idx - 1
          if index > 0 and index < 16:
         	ish_time=obd.u.cli.cl_import.imp_state_hist[index].ish_time
	  inflight=obd.u.cli.cl_import.imp_inflight.counter
          connect_cnt = obd.u.cli.cl_import.imp_conn_cnt

    print "0x%-17x %-22s\t%-22s\t 0x%-17x 0x%-17x %-10s %-10d %5d %5d" % \
          (Addr(obd),
          ll.obd2str(obd),
          nid,
          Addr(obd.u.cli),
          Addr(obd.u.cli.cl_import),
          impstate,
          ish_time,
          index,
          connect_cnt)
    if stats_flag:
        print
        rs.osc_rpc_stats_seq_show(Addr(obd.u.cli))
        print_separator(SEP_SIZE)
    return 0

def print_devices(devices, stats_flag):
    print_header()
    for obd in devices:
        if Addr(obd) == 0:
            break
        print_one_device(obd, stats_flag)
    print_separator(SEP_SIZE)

def obd_devs(args):
    if args.obd_device:
        devices = [readSU('struct obd_device', args.obd_device)]
    else:
        devices = readSymbol('obd_devs')
    print_devices(devices, args.stats_flag)

if __name__ == "__main__":
    description = "Displays the contents of global 'obd_devs'"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("obd_device", nargs="?", default = [], type=toint,
        help="print obd_device at argument address")
    parser.add_argument("-r", dest="stats_flag", action="count",
        help="print the rpc_stats sequence for each client_obd")
    args = parser.parse_args()
    obd_devs(args)
