#!/usr/bin/env python

import os, signal, sys, time

# recieved after the file has been deleted
# attempt to read the file and exit with status
def sigusr1(signum, frame):
    try:
        data = f.read()
    except Exception, e:
        print "keepopen: read failed", e
        sys.exit(1)

    f.close()
    if data == tag:
        print "keepopen: success: ", data
        sys.exit(0)
    else:
        print "keepopen: bad data: ", data
        sys.exit(2)

signal.signal(signal.SIGUSR1, sigusr1)

tag = "test data"
filename = sys.argv[1]
os.system("echo -n %s > %s" %(tag, filename))

f = open(filename, 'r')
while 1:
    time.sleep(10)
