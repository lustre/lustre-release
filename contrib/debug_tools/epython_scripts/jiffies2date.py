#!usr/bin/env python
from pykdump.API import *
"""
Copyright (c) 2019 Cray Inc. All Rights Reserved.
Utility to print jiffies as date and time
"""

import argparse
import time
import crashlib.time

description_short = "Print the date and time for a jiffies timestamp."

# Get current time in jiffies and in seconds. Compute the offset of
# the timestamp in jiffies from current time and convert to seconds.
# Subtract the offset from current time in seconds and convert result
# to a datetime string.
def jiffies2date(jts):
    scur = crashlib.time.get_wallclock_seconds()

    jcur = readSymbol('jiffies')
    if jts == 0:
        jts = jcur
    soffset = (jcur - int(jts)) / sys_info.HZ

    stime = scur - soffset
    date = time.asctime(time.localtime(stime))
    print '%s (epoch: %d)' % (date, stime)

if __name__ == "__main__":
    description = "Print the date and time of a given jiffies timestamp. " + \
                  "Also includes seconds since epoch."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("timestamp", nargs="?", default=0, type=int,
        help="the timestamp in jiffies to be converted to date/time")
    args = parser.parse_args()
    jiffies2date(args.timestamp)
