#!/usr/bin/env python
#
#  Copyright (C) 2002 Cluster File Systems, Inc.
#   Author: Robert Read <rread@clusterfs.com>
#   This file is part of Lustre, http://www.lustre.org.
#
#   Lustre is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License as published by the Free Software Foundation.
#
#   Lustre is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with Lustre; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

# Generic function reside here

import os, re, commands, sys, string, syslog, popen2, fcntl, select
import  sched, time, threading, signal, fileinput


def get_service_name(lctl_cmd, lproc_path, service):
    service_path = "%s/%s" % (lproc_path, service)
    if not os.access(service_path, os.R_OK):
        return None
    cmds = "%s  device_list"  % (lctl_cmd)
    tmp_name = service
    if service == 'ost': #OST service run as obdfilter
       tmp_name = 'obdfilter'
    rc, output = search_for_pattern(cmds, tmp_name)
    if rc != 0:
        return None
    tokens = string.split(output)
    service_name = tokens[3] #Gives configured device name
    return service_name
    
def check_process_status(pidfile_name):
    if not os.access(pidfile_name, os.R_OK):
        return 0
    pidfile = open(pidfile_name, 'r')
    pid = pidfile.readlines()
    pidfile.close()
    proc_entry = "/proc/%s" % (pid[0])
    if os.access(proc_entry, os.R_OK):
        status_file = "%s/status" % (proc_entry)
        proc_fd = open(status_file, 'r')
        status_line = proc_fd.readline()
        proc_fd.close()
        status_file_name = string.split(status_line)[1]
        tokens = string.split(sys.argv[0], '/')
        fname = tokens[len(tokens) - 1]
        if re.match(status_file_name, fname):
            return 1
    return 0

def search_for_pattern(cmd, pattern):
    rc, lines = execute_command(cmd)
    if rc == 0:
        lines = string.split(lines, '\n')
        for entry in lines:
            entry = string.strip(entry)
            if re.search(pattern, entry):
                return rc, entry
    else:
        return rc, lines

def execute_command(command):
    return commands.getstatusoutput(command)

def daemon_setup(cleanup_host):
    signal.signal(signal.SIGINT, cleanup_host)
    signal.signal(signal.SIGKILL, cleanup_host)
    signal.signal(signal.SIGQUIT, cleanup_host)
    signal.signal(signal.SIGILL, cleanup_host)
    os.setsid()
    os.close(0)
    os.close(1)
    os.close(2)

def create_pidfile(pidfile_name, pid):
    pidfile = open(pidfile_name, 'w')
    pidfile.write(str(pid))
    pidfile.close()

def find_exec_path(cmd, path_name, cwd):
    syspath = string.split(os.environ['PATH'], ':')
    cmdpath = os.path.dirname(cwd)
    syspath.insert(0, cmdpath);
    if path_name:
        syspath.insert(0, path_name)
    for d in syspath:
        prog = os.path.join(d,cmd)
        if os.access(prog, os.X_OK):
            return prog
    return ''

