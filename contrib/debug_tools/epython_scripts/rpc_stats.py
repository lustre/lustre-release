#!/usr/bin/env python

"""
Copyright (c) 2015-2018 Cray Inc. All Rights Reserved.
Utility to display rpc stats for a client_obd
"""

from pykdump.API import *
import argparse

import lustrelib as ll
from crashlib.input import toint

description_short = 'Dumps the rpc stats for a given client_obd'

OBD_HIST_MAX = 32

def get_cli_obd(client_obd):
    cli = None
    try:
        cli = readSU('struct client_obd', client_obd)
    except Exception, e:
        for dev in readSymbol('obd_devs'):
            try:
                if ll.obd2str(dev, 4) == client_obd:
                    cli = dev.u.cli
                    break
            except Exception, e:
                continue
    return cli

def pct(a, b):
    return 100 * a / b if b else 0

def lprocfs_oh_sum(oh):
    ret = 0
    for i in range(OBD_HIST_MAX):
        ret += oh.oh_buckets[i]
    return ret

def osc_rpc_stats_seq_show(client_obd):
    if not client_obd:
        print "invalid input for field 'client_obd'"
        return 1
    cli = readSU('struct client_obd', client_obd)
    print "read RPCs in flight:  %d" % cli.cl_r_in_flight
    print "write RPCs in flight: %d" % cli.cl_w_in_flight
    print "pending write pages:  %d" % cli.cl_pending_w_pages.counter
    print "pending read pages:   %d" % cli.cl_pending_r_pages.counter

    print "\n\t\t\tread\t\t\twrite"
    print "pages per rpc         rpcs   % cum % |       rpcs   % cum %\n"

    read_tot = lprocfs_oh_sum(cli.cl_read_page_hist)
    write_tot = lprocfs_oh_sum(cli.cl_write_page_hist)

    read_cum = 0
    write_cum = 0
    for i in range(OBD_HIST_MAX):
        r = cli.cl_read_page_hist.oh_buckets[i]
        w = cli.cl_write_page_hist.oh_buckets[i]

        read_cum += r
        write_cum += w
        print "%d:\t\t%10d %3d %3d   | %10d %3d %3d" % \
              (1 << i, r, pct(r, read_tot),
              pct(read_cum, read_tot), w,
              pct(w, write_tot),
              pct(write_cum, write_tot))
        if read_cum == read_tot and write_cum == write_tot:
            break

    print "\n\t\t\tread\t\t\twrite"
    print "rpcs in flight        rpcs   % cum % |       rpcs   % cum %\n"

    read_tot = lprocfs_oh_sum(cli.cl_read_rpc_hist)
    write_tot = lprocfs_oh_sum(cli.cl_write_rpc_hist)

    read_cum = 0
    write_cum = 0
    for i in range(OBD_HIST_MAX):
        r = cli.cl_read_rpc_hist.oh_buckets[i]
        w = cli.cl_write_rpc_hist.oh_buckets[i]

        read_cum += r
        write_cum += w
        print "%d:\t\t%10d %3d %3d   | %10d %3d %3d" % \
              (i, r, pct(r, read_tot),
              pct(read_cum, read_tot), w,
              pct(w, write_tot),
              pct(write_cum, write_tot))
        if read_cum == read_tot and write_cum == write_tot:
            break

    print "\n\t\t\tread\t\t\twrite"
    print "offset                rpcs   % cum % |       rpcs   % cum %\n"

    read_tot = lprocfs_oh_sum(cli.cl_read_offset_hist)
    write_tot = lprocfs_oh_sum(cli.cl_write_offset_hist)

    read_cum = 0
    write_cum = 0
    for i in range(OBD_HIST_MAX):
        r = cli.cl_read_offset_hist.oh_buckets[i]
        w = cli.cl_write_offset_hist.oh_buckets[i]

        read_cum += r
        write_cum += w
        offset = 0 if i == 0 else 1 << (i - 1)
        print "%d:      \t%10d %3d %3d   | %10d %3d %3d" % \
              (offset, r, pct(r, read_tot),
              pct(read_cum, read_tot), w,
              pct(w, write_tot),
              pct(write_cum, write_tot))
        if read_cum == read_tot and write_cum == write_tot:
            break
    print
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=description_short)
    parser.add_argument("client_obd", nargs="?", default=[], type=toint,
        help="address of client_obd structure whose stats will be dumped")
    args = parser.parse_args()
    cli = get_cli_obd(args.client_obd)
    osc_rpc_stats_seq_show(cli)
