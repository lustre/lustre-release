#!/usr/bin/python
#
# ltrap: Utility that sends lustre trap to management station.
# usage : ltrap <config_file>
# <config_file> is file which has list of management stations to send trap.
#               File format should be one name per line.
#
# It opens a pipe to /var/log/messages to read new messages, filter messages
# for lustre messages and then send trap to management station specified in
# config file.
#
# Author: Devendra Garg [ devendra@india.hp.com ]
#

import os, re, commands, sys, string, syslog, popen2, fcntl, select

if sys.version[0] == '1':
    from FCNTL import F_GETFL, F_SETFL
else:
    from fcntl import F_GETFL, F_SETFL

lustreLog = "/var/log/messages"
trapCmd = 'snmptrap'

def find_prog(cmd):
    syspath = string.split(os.environ['PATH'], ':')
    cmdpath = os.path.dirname(sys.argv[0])
    syspath.insert(0, cmdpath);
    syspath.insert(0, os.path.join(cmdpath, '../../portals/linux/utils/'))
    syspath.insert(0, os.path.join(cmdpath, '../lustre/utils/'))
    for d in syspath:
        prog = os.path.join(d,cmd)
        if os.access(prog, os.X_OK):
            return prog
    return ''

# ============================================================
# handle lctl interface
class LCTLInterface:
    """
    Manage communication with lctl
    """
    def __init__(self, cmd):
        """
        Initialize close by finding the lctl binary.
        """
        self.lctl = find_prog(cmd)
        self.save_file = ''
        if not self.lctl:
                print ('! lctl not found')
                self.lctl = 'lctl'
        else:
                print ('lctl', "unable to find lctl binary.")

    def use_save_file(self, file):
        self.save_file = file
        
    def set_nonblock(self, fd):
        fl = fcntl.fcntl(fd, F_GETFL)
        fcntl.fcntl(fd, F_SETFL, fl | os.O_NDELAY)

    def run(self, cmds):
        """
        run lctl
        the cmds are written to stdin of lctl
        lctl doesn't return errors when run in script mode, so
        stderr is checked
        should modify command line to accept multiple commands, or
        create complex command line options
        """
        cmd_line = self.lctl
        child = popen2.Popen3(cmd_line, 1) # Capture stdout and stderr from command
        child.tochild.write(cmds + "\n")
        child.tochild.close()

        # From "Python Cookbook" from O'Reilly
        outfile = child.fromchild
        outfd = outfile.fileno()
        self.set_nonblock(outfd)
        errfile = child.childerr
        errfd = errfile.fileno()
        self.set_nonblock(errfd)

        outdata = errdata = ''
        outeof = erreof = 0
        while 1:
            ready = select.select([outfd,errfd],[],[]) # Wait for input
            if outfd in ready[0]:
                outchunk = outfile.read()
                if outchunk == '': outeof = 1
                outdata = outdata + outchunk
            if errfd in ready[0]:
                errchunk = errfile.read()
                if errchunk == '': erreof = 1
                errdata = errdata + errchunk
            if outeof and erreof: break
        # end of "borrowed" code

        ret = child.wait()
        if os.WIFEXITED(ret):
            rc = os.WEXITSTATUS(ret)
        else:
            rc = 0
        if rc or len(errdata):
            print (self.lctl, errdata, rc)
        return rc, outdata

    def runcmd(self, *args):
        """
        run lctl using the command line
        """
        cmd = string.join(map(str,args))
        rc, out = self.run(cmd)
        if rc:
            print (self.lctl, out, rc)
        return rc, out

# ============================================================
# handle lmc interface
class CMDInterface:
    """
    Manage communication with commands
    """

    def __init__(self, cmd):
        """
        Initialize close by finding the lmc script.
        """
        self.prog = find_prog(cmd)
        if not self.prog:
                print "! %s not found" % (cmd)
                self.prog = cmd

    def run(self, cmds):
        """
        run lmc
        the cmds are written to stdin of lmc
        """
        cmd = (self.prog + cmds)
	f = os.popen (cmd)
	line = f.readlines()
	return line
	while line:
	    line = f.readline()


    def runcmd(self, *args):
        """
        run lmc using the command line
        """
        cmd = string.join(map(str,args))
        rc = self.run(cmd)
        return rc

config_file ="/tmp/abc.xml"

def genXml():
        
   LMC = CMDInterface('lmc')
   cmds = " -o %s --add node --node localhost " % (config_file)
   LMC.runcmd(cmds)
   cmds = " -m %s --add net --node localhost --nid localhost --nettype %s" %(config_file, "tcp")
   LMC.runcmd(cmds)
   cmds = " -m %s --add ost --ost obd1 --node localhost --osdtype=obdecho" % (config_file)
   LMC.runcmd(cmds)
   cmds = " -m %s --add echo_client --node localhost --ost obd1" %(config_file)
   LMC.runcmd(cmds)


def config_host():

   LCONF = CMDInterface('lconf')
   cmds = " -v --noexec --reformat %s" % (config_file)
   LCONF.runcmd(cmds)




def search_for_pattern(prog, cmd, pattern, index):

   lines = prog.runcmd(cmd)
   for entry in lines:
        entry = string.strip(entry)
        tokens = string.split(entry)
        if pattern == 'echo_client':
	    if tokens[index] == pattern :
                return entry
	    else:
	        print "echo client configuration has not done "
	if pattern == 'oid':
	    if len(tokens) == index:
	        return entry
	    else:
	        print "object not created successfully"


def check_ost_health():

   CMD  = CMDInterface('lctl')
   cmd = " device_list"
   output = search_for_pattern(CMD, cmd, "echo_client", 2)
   tokens = string.split(output)
   ECHO_NAME = tokens[3]
   cmd = " --device \$%s create 1" % (ECHO_NAME)
   output = search_for_pattern(CMD, cmd, "oid", 6)
   tokens = string.split(output)
   OID = tokens[5]


   lctl = LCTLInterface('lctl')
   cmds = (" --threads 2 v $%s test_brw 10 w -30 1 %s")% (ECHO_NAME, OID)
   rc, out = lctl.runcmd(cmds)
   if rc != 0:
	sendtrap("write failure ", rc)
   cmds = (" --threads 2 v $%s test_brw 10 r -30 1 %s")% (ECHO_NAME, OID)
   rc, out = lctl.runcmd(cmds)
   if rc != 0:
	sendtrap("read failure ", rc)

   cmds = (" --threads 1 v $%s test_getattr 10 -30 %s")% (ECHO_NAME, OID)
   rc, out = lctl.runcmd(cmds)
   if rc != 0:
	sendtrap("test getattr failure on object ", rc)
   cmds = (" --device $%s destroy %s")% (ECHO_NAME, OID)
   rc, out = lctl.runcmd(cmds)
   if rc != 0:
	sendtrap("destroy failure ", rc)
   else:
	sendtrap("helth ok", 1)


def sendtrap(err_msg, rc):
    global lastTrapSent
    global trapCmd
    global m_stations

    m_stations = "uml1"
    for station in m_stations:
        #trim new line
        if (station != '') and (station[ len(station)-1 ] == '\n' ): 
            station = station[:len(station)-1]        
        if station == '':
            continue

        snmptrap = "%s -v 1 %s public \".1.3.6\" \"\" \
6 2 \"\" \".1.3.6.1\" i %d   \".1.3.6.1\" s \"%s\"" % (trapCmd, "uml1", rc, \
err_msg)

        status = commands.getstatusoutput(snmptrap)
        if status[0] != 0:
            err = "Failed to send trap : " + snmptrap+'\nErr Msg ->' + status[1]
            syslog.syslog(syslog.LOG_ERR, err )

def main():

    global ECHO_CLIENT
    genXml()
    config_host()
    check_ost_health()


if __name__ == "__main__":
    main()

