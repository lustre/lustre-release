#!/usr/bin/env python
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
DEFAULT_TCPBUF = 1048576
DEFAULT_PORT = 899
m_stations = "lustre4.india.hp.com" /*Management station hostname need to be updated here*/

def find_prog(cmd):
    syspath = string.split(os.environ['PATH'], ':')
    cmdpath = os.path.dirname(sys.argv[0])
    syspath.insert(0, cmdpath);
    syspath.insert(0, os.path.join(cmdpath, '../../portals/linux/utils/'))
    syspath.insert(0, os.path.join(cmdpath, '../lustre/utils/'))
    syspath.insert(0, os.path.join(cmdpath, '../lustre/mdc/'))
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
        if not self.lctl:
                print ('! lctl not found')
                self.lctl = cmd
                print ('lctl', "unable to find lctl binary.")
                sys.exit(1)
        else:
                print ('lctl', "able to find lctl binary.")

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
	lines = f.readlines()
	rc = f.close()
	if rc:
	    return NULL
	else:
	    return lines


    def runcmd(self, *args):
        """
        run lmc using the command line
        """
        cmd = string.join(map(str,args))
        rc = self.run(cmd)
        return rc


def net_config(LCTL, hostname, netaddr, port, net_uuid, nettype):
        flags = ''
        cmds =  "\n  add_uuid %s %s %s" % (net_uuid, netaddr, nettype)
        cmds =  """%s          
  network %s
  send_mem %d
  recv_mem %d
  connect %s %d %s""" % (cmds, nettype,
             DEFAULT_TCPBUF,
             DEFAULT_TCPBUF,
             netaddr, DEFAULT_PORT, flags )

        cmds = cmds + "\n  quit"
        LCTL.runcmd(cmds)

def mdc_config(LCTL, mdc_name, mdc_uuid, mds_uuid, net_uuid):

     attach="%s %s %s" % ("mdc", mdc_name, mdc_uuid)
     setup ="%s %s" %(mds_uuid, net_uuid)
     cmds = """
  newdev
  attach %s
  setup %s
  quit""" % (attach, setup)
     LCTL.runcmd(cmds)


def config_host():

   CMD = CMDInterface('lctl')
   cmds = " device_list"  
   output = search_for_pattern(CMD , cmds, "mds", 2)
   tokens = string.split(output)
   mds_uuid = tokens[4]
   if mds_uuid:
      mdc_module = """ %s""" % (find_prog('mdc.o'))
      CMD = CMDInterface('insmod')
      CMD.runcmd(mdc_module)
      hostname = "localhost"
      netaddr = "127.0.0.1"
      nettype = "tcp"
      net_uuid = "localhost_uuid"
      port = 899
      LCTL = LCTLInterface('lctl')
      net_config(LCTL, hostname, netaddr, port, net_uuid, nettype)
      
      mdc_name = "localhost_mdc"
      mdc_uuid = (mdc_name + "_uuid")
      mdc_config(LCTL, mdc_name, mdc_uuid, mds_uuid, net_uuid)

def search_for_pattern(prog, cmd, pattern, index):

   lines = prog.runcmd(cmd)
   for entry in lines:
        entry = string.strip(entry)
        tokens = string.split(entry)
        if pattern == 'mds':
	    if tokens[index] == pattern :
                return entry
	    else:
	        print "mds configuration has not done "
                sys.exit(2)
	if pattern == 'mdc':
	    if tokens[index] == pattern :
                return entry
	    else:
	        print "mdc configuration has not done "
		sys.exit(3)


def check_mds_health():

   CMD  = CMDInterface('lctl')
   cmds = " device_list"
   output = search_for_pattern(CMD, cmds, "mdc", 2)
   tokens = string.split(output)
   mdc_name = tokens[3]
   #lctl = LCTLInterface('lctl')
   cmds = " --device \$%s statfs " % (mdc_name)
   cmds = cmds + "\n quit"
   rc, out = CMD.runcmd(cmds)
   if rc != 0:
	sendtrap("mds statfs failure ", rc)
   else:
	sendtrap("mds helth ok", 1)

def sendtrap(err_msg, rc):
    global lastTrapSent
    global trapCmd
    global m_stations

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

    config_host()
    check_mds_health()


if __name__ == "__main__":
    main()

