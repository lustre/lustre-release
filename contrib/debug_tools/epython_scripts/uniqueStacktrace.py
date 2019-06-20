#!/usr/bin/env python
"""
Copyright (c) 2015-2019 Cray Inc. All Rights Reserved.
Utility to print unique stack traces
"""

import re
import sys
import StringIO
import argparse
from pykdump.API import exec_crash_command

description_short = 'Print stack traces for each task.'

# outer loop indentifies PIDs
# inner loop looks for # until
# another PID is found
def sortInput(swapper, input):


    ps = re.compile("^PID:\s+(\d+)\s+TASK:\s+([0-9A-Fa-f]+).*")
    n = re.compile("^#")
    swap = re.compile((".*\"swapper/[0-9]+\""))
    info = dict()
    PID = ""
    STK = ""
    tmp = ""

    # Outer to check for PIDs
    # this loop never breaks;
    for line in input:
        line = line.strip()

        # Inner loop to check for # signs indicating lines we want.
        # Having two loops allow for the PID and TSK to be associated
        # with  a particular trace.
        # This loop breaks if a new PID is found (meaning the end of the
        # current trace) or if there are no more lines available
        while True:
            if ps.match(line): break;
            line = line.strip()
            if n.match(line):
                line = line.split()
                tmp += " ".join([line[2], line[3], line[4]])
                if len(line) == 6 : tmp += " " + line[5]
                tmp += '\n\t'
            line = input.readline()
            if not line: break

        if tmp :
            if tmp in info:
                info[tmp].append((PID,STK))
            else:
                info[tmp] = [(PID,STK)]

        m = ps.match(line)
        if m:
            PID, STK = m.group(1), m.group(2)
            tmp = ""

            # if it's swapper line move on
            # this prevents entry into inner loop
            if not swapper and swap.match(line):
                line = input.readline()

    sort = sorted(info.items(), key=lambda info: len(info[1]))
    return sort

def printRes(sort, printpid, printptr):
    """
    Prints out individual stack traces from lowest to highest.
    """
    for stack_trace, ptask_list in sort:
        if printpid and not printptr:
            print "PID: %s" % (', '.join(p[0] for p in ptask_list))
        elif printpid and printptr:
            print "PID, TSK: %s" % (', '.join(p[0] + ': ' + p[1] for p in ptask_list))
        elif not printpid and printptr:
            print "TSK: %s" % (', '.join(p[1] for p in ptask_list))
        print "TASKS: %d" %(len(ptask_list))
        print "\t%s" %(stack_trace)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--print-pid",
                        action="store_true", dest="printpid", default=False,
                        help="Print PIDS corresponding to each ST")
    parser.add_argument("-q", "--print-taskpntr",
                        action="store_true", dest="printptr", default=False,
                        help="Print the task pointers for each ST")
    parser.add_argument("-s", "--swapper",
                        action="store_true", dest="swapper", default=False,
                        help="Print swapper processes")
    parser.add_argument("task_select", metavar="task_selection", nargs="*",
                        help="task selection argument (passed to foreach cmd)")

    args = parser.parse_args()

    com = "foreach {ts:s} bt".format(ts=" ".join(args.task_select))

    result = exec_crash_command(com)
    input = StringIO.StringIO(result)
    printRes(sortInput(args.swapper, input), args.printpid, args.printptr)

if __name__ == '__main__':
    main()
