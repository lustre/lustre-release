#!/usr/bin/env python

import getopt, os, re, signal, string, sys, time
from threading import *
from unglobhosts import *

verbose = 0

class PingTimer(Thread):
    def __init__(self, timeout, ping):
        Thread.__init__(self)
        self.timeout = timeout
        self.ping = ping

    def run(self):
        time.sleep(self.timeout)
        try:
            os.kill(self.ping.pid, signal.SIGKILL)
        except:
            pass

class Ping(Thread):
    def __init__(self, hostname, requested_status, timeout):
        Thread.__init__(self)
        self.hostname = hostname
        self.req_status = requested_status
        self.nodestatus = None
        self.pid = None
        self.timeout = timeout
 
    def spawnping(self):
        try:
            pid = os.fork()
            if pid == 0:  # Child
                # Redirect stdout/stderr filedescriptors to /dev/null
                out = os.open('/dev/null', os.O_WRONLY)
                os.dup2(out, 1)
                os.dup2(out, 2)
                os.execlp('ping', 'ping', '-c', '1', self.hostname)
            else:  # Parent
                return pid
        except OSError, e:
            print "Fork/exec of ping failed: %d (%s)" % (e.errno, e.strerror)
            sys.exit(1)

    def run(self):
        end_time = time.time() + self.timeout
        while time.time() < end_time:
            timer = PingTimer(5, self)
            if verbose: print 'Pinging', self.hostname
            self.pid = self.spawnping()
            timer.start()
            rc = os.waitpid(self.pid, 0)[1]
            if rc == 0 and self.req_status == 0: # Node UP
                if verbose: print self.hostname, "is now UP"
                self.nodestatus = 0
                break
            if rc != 0 and self.req_status == 1: # Node DOWN
                if verbose: print self.hostname, "is now DOWN"
                self.nodestatus = 1
                break
            timer.join()

def abandon_ship(signum, frame):
    os._exit(1)

def main():
    num_hosts = 0
    timeout = 300
    global verbose

    try:
        opts, leftover = getopt.getopt(sys.argv[1:], "vn:t:", ["up", "down"])
    except getopt.GetoptError:
        sys.exit('Usage: pingstatus.py <--up|--down> [-v] [-t seconds] [-n numhosts] <host glob>')

    for opt, val in opts:
        if opt == '-n':
            num_hosts = int(val)
        elif opt == '-v':
            verbose = 1
        elif opt == '-t':
            timeout = int(val)
        elif opt == '--up':
            status = 0
        elif opt == '--down':
            status = 1

    if leftover == []:
        sys.exit('Usage: pingstatus.py <--up|--down> [-v] [-t seconds] [-n numhosts] <host glob>')

    hostlist = unglobhosts(leftover[0])

    signal.signal(signal.SIGINT, abandon_ship)

    if num_hosts == 0:
        num_hosts = len(hostlist)

    pingthreads = []
    for i in range(num_hosts):
        thread = Ping(hostlist[i], status, timeout)
        pingthreads.append(thread)

    for thread in pingthreads:
        thread.start()

    for thread in pingthreads:
        thread.join()
        if thread.nodestatus != status:
            if verbose:
                print 'Timeout exceeded: Node', thread.hostname, 'is still',
                if status == 1: print 'UP'
                else:          print 'DOWN'
            os._exit(1)

    if verbose:
        print 'All nodes are',
        if status == 0: print 'UP'
        else:           print 'DOWN'
    os._exit(0)

if __name__ == "__main__":
    main()
