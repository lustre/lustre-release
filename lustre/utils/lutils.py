
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
# lconf - lustre configuration tool
#
# lconf is the main driver script for starting and stopping
# lustre filesystem services.
#
# Based in part on the XML obdctl modifications done by Brian Behlendorf 

import sys, getopt
import string, os, stat, popen2, socket, time, random
import re, exceptions
import xml.dom.minidom

# Global parameters
TCP_ACCEPTOR = ''
MAXTCPBUF = 1048576
DEFAULT_TCPBUF = 1048576
#
# Maximum number of devices to search for.
# (the /dev/loop* nodes need to be created beforehand)
MAX_LOOP_DEVICES = 256


first_cleanup_error = 0
def cleanup_error(rc):
    global first_cleanup_error
    if not first_cleanup_error:
        first_cleanup_error = rc




# ============================================================
# Config parameters, encapsulated in a class
class Config:
    def __init__(self):
        # flags
        self._noexec = 0
        self._verbose = 0
        self._reformat = 0
        self._cleanup = 0
        self._gdb = 0
        self._nomod = 0
        self._nosetup = 0
        self._force = 0
        # parameters
        self._modules = None
        self._node = None
        self._url = None
        self._gdb_script = '/tmp/ogdb'
        self._debug_path = '/tmp/lustre-log'
        self._dump_file = None
        self._src_dir = None
	self._minlevel = 0
	self._maxlevel = 100
	self._ldap = 0

    def ldapadd(self, flag = None):
        if flag: self._ldap= flag
        return self._ldap

    def verbose(self, flag = None):
        if flag: self._verbose = flag
        return self._verbose

    def noexec(self, flag = None):
        if flag: self._noexec = flag
        return self._noexec

    def reformat(self, flag = None):
        if flag: self._reformat = flag
        return self._reformat

    def cleanup(self, flag = None):
        if flag: self._cleanup = flag
        return self._cleanup

    def gdb(self, flag = None):
        if flag: self._gdb = flag
        return self._gdb

    def nomod(self, flag = None):
        if flag: self._nomod = flag
        return self._nomod

    def nosetup(self, flag = None):
        if flag: self._nosetup = flag
        return self._nosetup

    def force(self, flag = None):
        if flag: self._force = flag
        return self._force

    def node(self, val = None):
        if val: self._node = val
        return self._node

    def url(self, val = None):
        if val: self._url = val
        return self._url

    def gdb_script(self):
        if os.path.isdir('/r'):
            return '/r' + self._gdb_script
        else:
            return self._gdb_script

    def debug_path(self):
        if os.path.isdir('/r'):
            return '/r' + self._debug_path
        else:
            return self._debug_path

    def src_dir(self, val = None):
        if val: self._src_dir = val
        return self._src_dir

    def dump_file(self, val = None):
        if val: self._dump_file = val
        return self._dump_file

    def minlevel(self, val = None):
        if val: self._minlevel = int(val)
        return self._minlevel

    def maxlevel(self, val = None):
        if val: self._maxlevel = int(val)
        return self._maxlevel



config = Config()

# ============================================================ 
# debugging and error funcs

def fixme(msg = "this feature"):
    raise LconfError, msg + ' not implmemented yet.'

def panic(*args):
    msg = string.join(map(str,args))
    if not config.noexec():
        raise LconfError(msg)
    else:
        print "! " + msg

def log(*args):
    msg = string.join(map(str,args))
    print msg

def logall(msgs):
    for s in msgs:
        print string.strip(s)

def debug(*args):
    if config.verbose():
        msg = string.join(map(str,args))
        print msg

# ============================================================
# locally defined exceptions
class CommandError (exceptions.Exception):
    def __init__(self, cmd_name, cmd_err, rc=None):
        self.cmd_name = cmd_name
        self.cmd_err = cmd_err
        self.rc = rc

    def dump(self):
        import types
        if type(self.cmd_err) == types.StringType:
            if self.rc:
                print "! %s (%d): %s" % (self.cmd_name, self.rc, self.cmd_err)
            else:
                print "! %s: %s" % (self.cmd_name, self.cmd_err)
        elif type(self.cmd_err) == types.ListType:
            if self.rc:
                print "! %s (error %d):" % (self.cmd_name, self.rc)
            else:
                print "! %s:" % (self.cmd_name)
            for s in self.cmd_err:
                print "> %s" %(string.strip(s))
        else:
            print self.cmd_err

class LconfError (exceptions.Exception):
    def __init__(self, args):
        self.args = args

# Determine full path to use for an external command
# searches dirname(argv[0]) first, then PATH
def find_prog(cmd):
    syspath = string.split(os.environ['PATH'], ':')
    cmdpath = os.path.dirname(sys.argv[0])
    syspath.insert(0, cmdpath);
    syspath.insert(0, os.path.join(cmdpath, '../../portals/linux/utils/'))
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
            if config.noexec():
                debug('! lctl not found')
                self.lctl = 'lctl'
            else:
                raise CommandError('lctl', "unable to find lctl binary.")

    def run(self, cmds):
        """
        run lctl
        the cmds are written to stdin of lctl
        lctl doesn't return errors when run in script mode, so
        stderr is checked
        should modify command line to accept multiple commands, or
        create complex command line options
        """
        debug("+", self.lctl, cmds)
        if config.noexec(): return (0, [])
        p = popen2.Popen3(self.lctl, 1)
        p.tochild.write(cmds + "\n")
        p.tochild.close()
        out = p.fromchild.readlines()
        err = p.childerr.readlines()
        ret = p.wait()
        if os.WIFEXITED(ret):
            rc = os.WEXITSTATUS(ret)
        else:
            rc = 0
        if rc or len(err):
            raise CommandError(self.lctl, err, rc)
        return rc, out

    def runcmd(self, *args):
        """
        run lctl using the command line
        """
        cmd = string.join(map(str,args))
        debug("+", self.lctl, cmd)
        rc, out = run(self.lctl, cmd)
        if rc:
            raise CommandError(self.lctl, out, rc)
        return rc, out

            
    def network(self, net, nid):
        """ initialized network and add "self" """
        # Idea: "mynid" could be used for all network types to add "self," and then
        # this special case would be gone and the "self" hack would be hidden.
        global lctl
        if net  in ('tcp', 'toe'):
            cmds =  """
  network %s
  mynid %s
  add_uuid self %s
  quit""" % (net, nid, nid)
        else:
            cmds =  """
  network %s
  add_uuid self %s
  quit""" % (net, nid)
            
        self.run(cmds)

    # create a new connection
    def connect(self, net, nid, port, servuuid, send_mem, recv_mem):
        if net  in ('tcp', 'toe'):
            cmds =  """
  network %s
  add_uuid %s %s
  send_mem %d
  recv_mem %d
  connect %s %d
  quit""" % (net, servuuid, nid, send_mem, recv_mem, nid, port,  )
        else:
            cmds =  """
  network %s
  add_uuid %s %s
  connect %s %d
  quit""" % (net, servuuid, nid, nid, port,  )
            
        self.run(cmds)
                
    # add a route to a range
    def add_route(self, net, gw, lo, hi):
        cmds =  """
  network %s
  add_route %s %s %s
  quit  """ % (net, gw, lo, hi)
        self.run(cmds)

                
    def del_route(self, net, gw, lo, hi):
        cmds =  """
  ignore_errors
  network %s
  del_route %s
  quit  """ % (net, lo)
        self.run(cmds)

    # add a route to a host
    def add_route_host(self, net, uuid, gw, tgt):
        cmds =  """
  network %s
  add_uuid %s %s
  add_route %s %s
  quit """ % (net, uuid, tgt, gw, tgt)
        self.run(cmds)

    # add a route to a range
    def del_route_host(self, net, uuid, gw, tgt):
        cmds =  """
  ignore_errors
  network %s
  del_uuid %s
  del_route %s
  quit  """ % (net, uuid, tgt)
        self.run(cmds)

    # disconnect one connection
    def disconnect(self, net, nid, port, servuuid):
        cmds =  """
  ignore_errors
  network %s
  disconnect %s 
  del_uuid %s
  quit""" % (net, nid, servuuid)
        self.run(cmds)

    # disconnect all
    def disconnectAll(self, net):
        cmds =  """
  ignore_errors
  network %s
  del_uuid self
  disconnect
  quit""" % (net)
        self.run(cmds)

    # create a new device with lctl
    def newdev(self, attach, setup = ""):
        cmds = """
  newdev
  attach %s
  setup %s
  quit""" % (attach, setup)
        self.run(cmds)

    # cleanup a device
    def cleanup(self, name, uuid):
        cmds = """
  ignore_errors
  device $%s
  cleanup
  detach %s
  quit""" % (name, ('', 'force')[config.force()])
        self.run(cmds)

    # create an lov
    def lov_setconfig(self, uuid, mdsuuid, stripe_cnt, stripe_sz, stripe_off, pattern, devlist):
        cmds = """
  device $%s
  probe
  lov_setconfig %s %d %d %d %s %s
  quit""" % (mdsuuid, uuid, stripe_cnt, stripe_sz, stripe_off, pattern, devlist)
        self.run(cmds)

    # dump the log file
    def dump(self, dump_file):
        cmds = """
  debug_kernel %s 1
  quit""" % (dump_file)
        self.run(cmds)

    # get list of devices
    def device_list(self):
        rc, out = self.runcmd('device_list')
        return out

lctl = LCTLInterface('lctl')
# ============================================================
# Various system-level functions
# (ideally moved to their own module)

# Run a command and return the output and status.
# stderr is sent to /dev/null, could use popen3 to
# save it if necessary
def run(*args):
    cmd = string.join(map(str,args))
    debug ("+", cmd)
    if config.noexec(): return (0, [])
    f = os.popen(cmd + ' 2>&1')
    out = f.readlines()
    ret = f.close()
    if ret:
        ret = ret >> 8
    else:
        ret = 0
    return (ret, out)

# Run a command in the background.
def run_daemon(*args):
    cmd = string.join(map(str,args))
    debug ("+", cmd)
    if config.noexec(): return 0
    f = os.popen(cmd + ' 2>&1')
    ret = f.close()
    if ret:
        ret = ret >> 8
    else:
        ret = 0
    return ret


# Recursively look for file starting at base dir
def do_find_file(base, mod):
    fullname = os.path.join(base, mod)
    if os.access(fullname, os.R_OK):
        return fullname
    for d in os.listdir(base):
        dir = os.path.join(base,d)
        if os.path.isdir(dir):
            module = do_find_file(dir, mod)
            if module:
                return module

def find_module(src_dir, dev_dir, modname):
    mod = '%s.o' % (modname)
    module = src_dir +'/'+ dev_dir +'/'+ mod
    try: 
       if os.access(module, os.R_OK):
            return module
    except OSError:
        pass
    return None

# is the path a block device?
def is_block(path):
    s = ()
    try:
        s =  os.stat(path)
    except OSError:
        return 0
    return stat.S_ISBLK(s[stat.ST_MODE])

# build fs according to type
# fixme: dangerous
def mkfs(fstype, dev):
    if(fstype in ('ext3', 'extN')):
        mkfs = 'mkfs.ext2 -j -b 4096'
    else:
        print 'unsupported fs type: ', fstype
    if not is_block(dev):
        force = '-F'
    else:
        force = ''
    (ret, out) = run (mkfs, force, dev)
    if ret:
        panic("Unable to build fs:", dev)
    # enable hash tree indexing on fsswe
    # FIXME: this check can probably go away on 2.5
    if fstype == 'extN':
        htree = 'echo "feature FEATURE_C5" | debugfs -w'
        (ret, out) = run (htree, dev)
        if ret:
            panic("Unable to enable htree:", dev)

# some systems use /dev/loopN, some /dev/loop/N
def loop_base():
    import re
    loop = '/dev/loop'
    if not os.access(loop + str(0), os.R_OK):
        loop = loop + '/'
        if not os.access(loop + str(0), os.R_OK):
            panic ("can't access loop devices")
    return loop
    
# find loop device assigned to thefile
def find_loop(file):
    loop = loop_base()
    for n in xrange(0, MAX_LOOP_DEVICES):
        dev = loop + str(n)
        if os.access(dev, os.R_OK):
            (stat, out) = run('losetup', dev)
            if (out and stat == 0):
                m = re.search(r'\((.*)\)', out[0])
                if m and file == m.group(1):
                    return dev
        else:
            break
    return ''

# create file if necessary and assign the first free loop device
def init_loop(file, size, fstype):
    dev = find_loop(file)
    if dev:
        print 'WARNING file:', file, 'already mapped to', dev
        return dev
    if config.reformat()  or not os.access(file, os.R_OK | os.W_OK):
        run("dd if=/dev/zero bs=1k count=0 seek=%d of=%s" %(size,  file))
    loop = loop_base()
    # find next free loop
    for n in xrange(0, MAX_LOOP_DEVICES):
        dev = loop + str(n)
        if os.access(dev, os.R_OK):
            (stat, out) = run('losetup', dev)
            if (stat):
                run('losetup', dev, file)
                return dev
        else:
            print "out of loop devices"
            return ''
    print "out of loop devices"
    return ''

# undo loop assignment
def clean_loop(file):
    dev = find_loop(file)
    if dev:
        ret, out = run('losetup -d', dev)
        if ret:
            log('unable to clean loop device:', dev, 'for file:', file)
            logall(out)

# determine if dev is formatted as a <fstype> filesystem
def need_format(fstype, dev):
    # FIXME don't know how to implement this    
    return 0

# initialize a block device if needed
def block_dev(dev, size, fstype, format):
    if config.noexec(): return dev
    if not is_block(dev):
        dev = init_loop(dev, size, fstype)
    if config.reformat() or (need_format(fstype, dev) and format == 'yes'):
        mkfs(fstype, dev)

#    else:
#        panic("device:", dev,
#              "not prepared, and autoformat is not set.\n",
#              "Rerun with --reformat option to format ALL filesystems")
        
    return dev

def if2addr(iface):
    """lookup IP address for an interface"""
    rc, out = run("/sbin/ifconfig", iface)
    if rc or not out:
       return None
    addr = string.split(out[1])[1]
    ip = string.split(addr, ':')[1]
    return ip

def get_local_address(net_type, wildcard):
    """Return the local address for the network type."""
    local = ""
    if net_type in ('tcp', 'toe'):
        if  ':' in wildcard:
            iface, star = string.split(wildcard, ':')
            local = if2addr(iface)
            if not local:
                panic ("unable to determine ip for:", wildcard)
        else:
            host = socket.gethostname()
            local = socket.gethostbyname(host)
    elif net_type == 'elan':
        # awk '/NodeId/ { print $2 }' '/proc/elan/device0/position'
        try:
            fp = open('/proc/elan/device0/position', 'r')
            lines = fp.readlines()
            fp.close()
            for l in lines:
                a = string.split(l)
                if a[0] == 'NodeId':
                    local = a[1]
                    break
        except IOError, e:
            log(e)
    elif net_type == 'gm':
        fixme("automatic local address for GM")
    return local
        

def is_prepared(uuid):
    """Return true if a device exists for the uuid"""
    # expect this format:
    # 1 UP ldlm ldlm ldlm_UUID 2
    try:
        out = lctl.device_list()
        for s in out:
            if uuid == string.split(s)[4]:
                return 1
    except CommandError, e:
        e.dump()
    return 0
    


############################################################
# MDC UUID hack - 
# FIXME: clean this mess up!
#
saved_mdc = {}
def prepare_mdc(dom_node, mds_uuid):
    global saved_mdc
    mds_node = lookup(dom_node, mds_uuid);
    if not mds_node:
        panic("no mds:", mds_uuid)
    if saved_mdc.has_key(mds_uuid):
        return saved_mdc[mds_uuid]
    mdc = MDC(mds_node)
    mdc.prepare()
    saved_mdc[mds_uuid] = mdc.uuid
    return mdc.uuid

def cleanup_mdc(dom_node, mds_uuid):
    global saved_mdc
    mds_node = lookup(dom_node, mds_uuid);
    if not mds_node:
        panic("no mds:", mds_uuid)
    if not saved_mdc.has_key(mds_uuid):
        mdc = MDC(mds_node)
        mdc.cleanup()
        saved_mdc[mds_uuid] = mdc.uuid
        
    
# ============================================================
# Classes to prepare and cleanup the various objects
#
class Module:
    """ Base class for the rest of the modules. The default cleanup method is
    defined here, as well as some utilitiy funcs.
    """
    def __init__(self, module_name, dom_node):
        self.dom_node = dom_node
        self.module_name = module_name
        self.name = get_attr(dom_node, 'name')
        self.uuid = get_attr(dom_node, 'uuid')
        self.kmodule_list = []
        self._server = None
        self._connected = 0
        
    def info(self, *args):
        msg = string.join(map(str,args))
        print self.module_name + ":", self.name, self.uuid, msg


    def lookup_server(self, srv_uuid):
        """ Lookup a server's network information """
        net = get_ost_net(self.dom_node.parentNode, srv_uuid)
        if not net:
            panic ("Unable to find a server for:", srv_uuid)
        self._server = Network(net)

    def get_server(self):
        return self._server

    def cleanup(self):
        """ default cleanup, used for most modules """
        self.info()
        srv = self.get_server()
        if srv and local_net(srv):
            try:
                lctl.disconnect(srv.net_type, srv.nid, srv.port, srv.uuid)
            except CommandError, e:
                log(self.module_name, "disconnect failed: ", self.name)
                e.dump()
                cleanup_error(e.rc)
        try:
            lctl.cleanup(self.name, self.uuid)
        except CommandError, e:
            log(self.module_name, "cleanup failed: ", self.name)
            e.dump()
            cleanup_error(e.rc)

    def add_module(self, dev_dir, modname):
        """Append a module to list of modules to load."""
        self.kmodule_list.append((dev_dir, modname))

    def mod_loaded(self, modname):
        """Check if a module is already loaded. Look in /proc/modules for it."""
        fp = open('/proc/modules')
        lines = fp.readlines()
        fp.close()
        # please forgive my tired fingers for this one
        ret = filter(lambda word, mod=modname: word == mod,
                     map(lambda line: string.split(line)[0], lines))
        return ret

    def load_module(self):
        """Load all the modules in the list in the order they appear."""
        for dev_dir, mod in self.kmodule_list:
            #  (rc, out) = run ('/sbin/lsmod | grep -s', mod)
            if self.mod_loaded(mod) and not config.noexec():
                continue
            log ('loading module:', mod)
            if config.src_dir():
                module = find_module(config.src_dir(),dev_dir,  mod)
                if not module:
                    panic('module not found:', mod)
                (rc, out)  = run('/sbin/insmod', module)
                if rc:
                    raise CommandError('insmod', out, rc)
            else:
                (rc, out) = run('/sbin/modprobe', mod)
                if rc:
                    raise CommandError('modprobe', out, rc)
            
    def cleanup_module(self):
        """Unload the modules in the list in reverse order."""
        rev = self.kmodule_list
        rev.reverse()
        for dev_dir, mod in rev:
            if not self.mod_loaded(mod):
                continue
            # debug hack
            if mod == 'portals' and config.dump_file():
                lctl.dump(config.dump_file())
            log('unloading module:', mod)
            if config.noexec():
                continue
            (rc, out) = run('/sbin/rmmod', mod)
            if rc:
                log('! unable to unload module:', mod)
                logall(out)
        

class Network(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'NETWORK', dom_node)
        self.net_type = get_attr(dom_node,'type')
        self.nid = get_text(dom_node, 'server', '*')
        self.port = get_text_int(dom_node, 'port', 0)
        self.send_mem = get_text_int(dom_node, 'send_mem', DEFAULT_TCPBUF)
        self.recv_mem = get_text_int(dom_node, 'recv_mem', DEFAULT_TCPBUF)
        if '*' in self.nid:
            self.nid = get_local_address(self.net_type, self.nid)
            if not self.nid:
                panic("unable to set nid for", self.net_type, self.nid)
            debug("nid:", self.nid)

	if config.ldapadd():
		return

        self.add_module('portals/linux/oslib/', 'portals')
        if node_needs_router():
            self.add_module('portals/linux/router', 'kptlrouter')
        if self.net_type == 'tcp':
            self.add_module('portals/linux/socknal', 'ksocknal')
        if self.net_type == 'toe':
            self.add_module('portals/linux/toenal', 'ktoenal')
        if self.net_type == 'elan':
            self.add_module('portals/linux/rqswnal', 'kqswnal')
        if self.net_type == 'gm':
            self.add_module('portals/linux/gmnal', 'kgmnal')
        self.add_module('lustre/obdclass', 'obdclass')
        self.add_module('lustre/ptlrpc', 'ptlrpc')

    def prepare(self):
        global lctl 
        self.info(self.net_type, self.nid, self.port)
        if self.net_type in ('tcp', 'toe'):
            nal_id = '' # default is socknal
            if self.net_type == 'toe':
                nal_id = '-N 4'
            ret, out = run(TCP_ACCEPTOR, '-s', self.send_mem, '-r', self.recv_mem, nal_id, self.port)
            if ret:
                raise CommandError(TCP_ACCEPTOR, out, ret)
        ret = self.dom_node.getElementsByTagName('route_tbl')
        for a in ret:
            for r in a.getElementsByTagName('route'):
                net_type = get_attr(r, 'type')
                gw = get_attr(r, 'gw')
                lo = get_attr(r, 'lo')
                hi = get_attr(r,'hi', '')
                lctl.add_route(net_type, gw, lo, hi)
                if net_type in ('tcp', 'toe') and net_type == self.net_type and hi == '':
                    srv = nid2server(self.dom_node.parentNode.parentNode, lo)
                    if not srv:
                        panic("no server for nid", lo)
                    else:
                        lctl.connect(srv.net_type, srv.nid, srv.port, srv.uuid, srv.send_mem, srv.recv_mem)

        lctl.network(self.net_type, self.nid)
        lctl.newdev(attach = "ptlrpc RPCDEV RPCDEV_UUID")

    def cleanup(self):
        self.info(self.net_type, self.nid, self.port)
        ret = self.dom_node.getElementsByTagName('route_tbl')
        for a in ret:
            for r in a.getElementsByTagName('route'):
                lo = get_attr(r, 'lo')
                hi = get_attr(r,'hi', '')
                if self.net_type in ('tcp', 'toe') and hi == '':
                    srv = nid2server(self.dom_node.parentNode.parentNode, lo)
                    if not srv:
                        panic("no server for nid", lo)
                    else:
                        try:
                            lctl.disconnect(srv.net_type, srv.nid, srv.port, srv.uuid)
                        except CommandError, e:
                            print "disconnect failed: ", self.name
                            e.dump()
                            cleanup_error(e.rc)
                try:
                    lctl.del_route(self.net_type, self.nid, lo, hi)
                except CommandError, e:
                    print "del_route failed: ", self.name
                    e.dump()
                    cleanup_error(e.rc)
              
        try:
            lctl.cleanup("RPCDEV", "RPCDEV_UUID")
        except CommandError, e:
            print "cleanup failed: ", self.name
            e.dump()
            cleanup_error(e.rc)
        try:
            lctl.disconnectAll(self.net_type)
        except CommandError, e:
            print "disconnectAll failed: ", self.name
            e.dump()
            cleanup_error(e.rc)
        if self.net_type in ('tcp', 'toe'):
            # yikes, this ugly! need to save pid in /var/something
            run("killall acceptor")

class LDLM(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'LDLM', dom_node)
	if config.ldapadd():
		return
        self.add_module('lustre/ldlm', 'ldlm')
    def prepare(self):
        if is_prepared(self.uuid):
            return
        self.info()
        lctl.newdev(attach="ldlm %s %s" % (self.name, self.uuid),
                    setup ="")

class LOV(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'LOV', dom_node)
        self.mds_uuid = get_first_ref(dom_node, 'mds')
        mds= lookup(dom_node.parentNode, self.mds_uuid)
        self.mds_name = getName(mds)
        devs = dom_node.getElementsByTagName('devices')
        if len(devs) > 0:
            dev_node = devs[0]
            self.stripe_sz = get_attr_int(dev_node, 'stripesize', 65536)
            self.stripe_off = get_attr_int(dev_node, 'stripeoffset', 0)
            self.pattern = get_attr_int(dev_node, 'pattern', 0)
            self.devlist = get_all_refs(dev_node, 'osc')
            self.stripe_cnt = get_attr_int(dev_node, 'stripecount', len(self.devlist))
	if config.ldapadd():
		return
        self.add_module('lustre/mdc', 'mdc')
        self.add_module('lustre/lov', 'lov')

    def prepare(self):
        if is_prepared(self.uuid):
            return
        for osc_uuid in self.devlist:
            osc = lookup(self.dom_node.parentNode, osc_uuid)
            if osc:
                n = OSC(osc)
                n.prepare()
            else:
                panic('osc not found:', osc_uuid)
        mdc_uuid = prepare_mdc(self.dom_node.parentNode, self.mds_uuid)
        self.info(self.mds_uuid, self.stripe_cnt, self.stripe_sz,
                  self.stripe_off, self.pattern, self.devlist, self.mds_name)
        lctl.newdev(attach="lov %s %s" % (self.name, self.uuid),
                    setup ="%s" % (mdc_uuid))

    def cleanup(self):
        if not is_prepared(self.uuid):
            return
        for osc_uuid in self.devlist:
            osc = lookup(self.dom_node.parentNode, osc_uuid)
            if osc:
                n = OSC(osc)
                n.cleanup()
            else:
                panic('osc not found:', osc_uuid)
        Module.cleanup(self)
        cleanup_mdc(self.dom_node.parentNode, self.mds_uuid)


    def load_module(self):
        for osc_uuid in self.devlist:
            osc = lookup(self.dom_node.parentNode, osc_uuid)
            if osc:
                n = OSC(osc)
                n.load_module()
                break
            else:
                panic('osc not found:', osc_uuid)
        Module.load_module(self)


    def cleanup_module(self):
        Module.cleanup_module(self)
        for osc_uuid in self.devlist:
            osc = lookup(self.dom_node.parentNode, osc_uuid)
            if osc:
                n = OSC(osc)
                n.cleanup_module()
                break
            else:
                panic('osc not found:', osc_uuid)

class LOVConfig(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'LOVConfig', dom_node)
        self.lov_uuid = get_first_ref(dom_node, 'lov')
        l = lookup(dom_node.parentNode, self.lov_uuid)
        self.lov = LOV(l)
        
    def prepare(self):
        lov = self.lov
        self.info(lov.mds_uuid, lov.stripe_cnt, lov.stripe_sz, lov.stripe_off,
                  lov.pattern, lov.devlist, lov.mds_name)
        lctl.lov_setconfig(lov.uuid, lov.mds_name, lov.stripe_cnt,
			   lov.stripe_sz, lov.stripe_off, lov.pattern,
			   string.join(lov.devlist))

    def cleanup(self):
        #nothing to do here
        pass


class MDS(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'MDS', dom_node)
        self.devname, self.size = get_device(dom_node)
        self.fstype = get_text(dom_node, 'fstype')
        # FIXME: if fstype not set, then determine based on kernel version
        self.format = get_text(dom_node, 'autoformat', "no")
	if config.ldapadd():
		return
        if self.fstype == 'extN':
            self.add_module('lustre/extN', 'extN') 
        self.add_module('lustre/mds', 'mds')
        self.add_module('lustre/mds', 'mds_%s' % (self.fstype))
            
    def prepare(self):
        if is_prepared(self.uuid):
            return
        self.info(self.devname, self.fstype, self.format)
        blkdev = block_dev(self.devname, self.size, self.fstype, self.format)
        if not is_prepared('MDT_UUID'):
            lctl.newdev(attach="mdt %s %s" % ('MDT', 'MDT_UUID'),
                        setup ="")
        lctl.newdev(attach="mds %s %s" % (self.name, self.uuid),
                    setup ="%s %s" %(blkdev, self.fstype))
    def cleanup(self):
        if is_prepared('MDT_UUID'):
            try:
                lctl.cleanup("MDT", "MDT_UUID")
            except CommandError, e:
                print "cleanup failed: ", self.name
                e.dump()
                cleanup_error(e.rc)
        if not is_prepared(self.uuid):
            return
        Module.cleanup(self)
        clean_loop(self.devname)

# Very unusual case, as there is no MDC element in the XML anymore
# Builds itself from an MDS node
class MDC(Module):
    def __init__(self,dom_node):
        self.mds = MDS(dom_node)
        self.dom_node = dom_node
        self.module_name = 'MDC'
        self.kmodule_list = []
        self._server = None
        self._connected = 0

        host = socket.gethostname()
        self.name = 'MDC_%s' % (self.mds.name)
        self.uuid = '%s_%05x_%05x' % (self.name, int(random.random() * 1048576),
                                      int(random.random() * 1048576))

        self.lookup_server(self.mds.uuid)
	if config.ldapadd():
		return
        self.add_module('lustre/mdc', 'mdc')

    def prepare(self):
        if is_prepared(self.uuid):
            return
        self.info(self.mds.uuid)
        srv = self.get_server()
        lctl.connect(srv.net_type, srv.nid, srv.port, srv.uuid, srv.send_mem, srv.recv_mem)
        lctl.newdev(attach="mdc %s %s" % (self.name, self.uuid),
                        setup ="%s %s" %(self.mds.uuid, srv.uuid))
            
class OBD(Module):
    def __init__(self, dom_node):
        Module.__init__(self, 'OBD', dom_node)
        self.obdtype = get_attr(dom_node, 'type')
        self.devname, self.size = get_device(dom_node)
        self.fstype = get_text(dom_node, 'fstype')
        # FIXME: if fstype not set, then determine based on kernel version
        self.format = get_text(dom_node, 'autoformat', 'yes')
	if config.ldapadd():
		return
        if self.fstype == 'extN':
            self.add_module('lustre/extN', 'extN') 
        self.add_module('lustre/' + self.obdtype, self.obdtype)

    # need to check /proc/mounts and /etc/mtab before
    # formatting anything.
    # FIXME: check if device is already formatted.
    def prepare(self):
        if is_prepared(self.uuid):
            return
        self.info(self.obdtype, self.devname, self.size, self.fstype, self.format)
        if self.obdtype == 'obdecho':
            blkdev = ''
        else:
            blkdev = block_dev(self.devname, self.size, self.fstype, self.format)
        lctl.newdev(attach="%s %s %s" % (self.obdtype, self.name, self.uuid),
                    setup ="%s %s" %(blkdev, self.fstype))
    def cleanup(self):
        if not is_prepared(self.uuid):
            return
        Module.cleanup(self)
        if not self.obdtype == 'obdecho':
            clean_loop(self.devname)

class OST(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'OST', dom_node)
        self.obd_uuid = get_first_ref(dom_node, 'obd')
	if config.ldapadd():
		return
        self.add_module('lustre/ost', 'ost')

    def prepare(self):
        if is_prepared(self.uuid):
            return
        self.info(self.obd_uuid)
        lctl.newdev(attach="ost %s %s" % (self.name, self.uuid),
                    setup ="%s" % (self.obd_uuid))


# virtual interface for  OSC and LOV
class VOSC(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'VOSC', dom_node)
        if dom_node.nodeName == 'lov':
            self.osc = LOV(dom_node)
        else:
            self.osc = OSC(dom_node)
    def prepare(self):
        self.osc.prepare()
    def cleanup(self):
        self.osc.cleanup()
    def load_module(self):
        self.osc.load_module()
    def cleanup_module(self):
        self.osc.cleanup_module()
        

class OSC(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'OSC', dom_node)
        self.obd_uuid = get_first_ref(dom_node, 'obd')
        self.ost_uuid = get_first_ref(dom_node, 'ost')
        self.lookup_server(self.ost_uuid)
	if config.ldapadd():
		return
        self.add_module('lustre/osc', 'osc')

    def prepare(self):
        if is_prepared(self.uuid):
            return
        self.info(self.obd_uuid, self.ost_uuid)
        srv = self.get_server()
        if local_net(srv):
            lctl.connect(srv.net_type, srv.nid, srv.port, srv.uuid, srv.send_mem, srv.recv_mem)
        else:
            r =  find_route(srv)
            if r:
                lctl.add_route_host(r[0], srv.uuid, r[1], r[2])
            else:
                panic ("no route to",  srv.nid)
            
        lctl.newdev(attach="osc %s %s" % (self.name, self.uuid),
                    setup ="%s %s" %(self.obd_uuid, srv.uuid))

    def cleanup(self):
        if not is_prepared(self.uuid):
            return
        srv = self.get_server()
        if local_net(srv):
            Module.cleanup(self)
        else:
            self.info(self.obd_uuid, self.ost_uuid)
            r =  find_route(srv)
            if r:
                try:
                    lctl.del_route_host(r[0], srv.uuid, r[1], r[2])
                except CommandError, e:
                    print "del_route failed: ", self.name
                    e.dump()
                    cleanup_error(e.rc)
            Module.cleanup(self)
            

class ECHO_CLIENT(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'ECHO_CLIENT', dom_node)
        self.obd_uuid = get_first_ref(dom_node, 'osc')
        debug("HERE",self.obd_uuid)
        self.add_module('lustre/obdecho', 'obdecho')

    def prepare(self):
        if is_prepared(self.uuid):
            return
        self.info(self.obd_uuid)
            
        lctl.newdev(attach="echo_client %s %s" % (self.name, self.uuid),
                    setup = self.obd_uuid)

    def cleanup(self):
        if not is_prepared(self.uuid):
            return
        Module.cleanup(self)


class Mountpoint(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'MTPT', dom_node)
        self.path = get_text(dom_node, 'path')
        self.mds_uuid = get_first_ref(dom_node, 'mds')
        self.lov_uuid = get_first_ref(dom_node, 'osc')
        l = lookup(self.dom_node.parentNode, self.lov_uuid)
        self.osc = VOSC(l)
	if config.ldapadd():
		return
        self.add_module('lustre/mdc', 'mdc')
        self.add_module('lustre/llite', 'llite')

    def prepare(self):
        self.osc.prepare()
        mdc_uuid = prepare_mdc(self.dom_node.parentNode, self.mds_uuid)
        self.info(self.path, self.mds_uuid, self.lov_uuid)
        cmd = "mount -t lustre_lite -o osc=%s,mdc=%s none %s" % \
              (self.lov_uuid, mdc_uuid, self.path)
        run("mkdir", self.path)
        ret, val = run(cmd)
        if ret:
            panic("mount failed:", self.path)

    def cleanup(self):
        self.info(self.path, self.mds_uuid,self.lov_uuid)
        if config.force():
            (rc, out) = run("umount -f", self.path)
        else:
            (rc, out) = run("umount", self.path)
        if rc:
            log("umount failed, cleanup will most likely not work.")
        l = lookup(self.dom_node.parentNode, self.lov_uuid)
        self.osc.cleanup()
        cleanup_mdc(self.dom_node.parentNode, self.mds_uuid)

    def load_module(self):
        self.osc.load_module()
        Module.load_module(self)
    def cleanup_module(self):
        Module.cleanup_module(self)
        self.osc.cleanup_module()


# ============================================================
# XML processing and query
# TODO: Change query funcs to use XPath, which is muc cleaner

def get_device(obd):
    list = obd.getElementsByTagName('device')
    if len(list) > 0:
        dev = list[0]
        dev.normalize();
        size = get_attr_int(dev, 'size', 0)
        return dev.firstChild.data, size
    return '', 0

# Get the text content from the first matching child
# If there is no content (or it is all whitespace), return
# the default
def get_text(dom_node, tag, default=""):
    list = dom_node.getElementsByTagName(tag)
    if len(list) > 0:
        dom_node = list[0]
        dom_node.normalize()
        if dom_node.firstChild:
            txt = string.strip(dom_node.firstChild.data)
            if txt:
                return txt
    return default

def get_text_int(dom_node, tag, default=0):
    list = dom_node.getElementsByTagName(tag)
    n = default
    if len(list) > 0:
        dom_node = list[0]
        dom_node.normalize()
        if dom_node.firstChild:
            txt = string.strip(dom_node.firstChild.data)
            if txt:
                try:
                    n = int(txt)
                except ValueError:
                    panic("text value is not integer:", txt)
    return n

def get_attr(dom_node, attr, default=""):
    v = dom_node.getAttribute(attr)
    if v:
        return v
    return default

def get_attr_int(dom_node, attr, default=0):
    n = default
    v = dom_node.getAttribute(attr)
    if v:
        try:
            n = int(v)
        except ValueError:
            panic("attr value is not integer", v)
    return n

def get_first_ref(dom_node, tag):
    """ Get the first uuidref of the type TAG. Used one only
    one is expected.  Returns the uuid."""
    uuid = None
    refname = '%s_ref' % tag
    list = dom_node.getElementsByTagName(refname)
    if len(list) > 0:
        uuid = getRef(list[0])
    return uuid
    
def get_all_refs(dom_node, tag):
    """ Get all the refs of type TAG.  Returns list of uuids. """
    uuids = []
    refname = '%s_ref' % tag
    list = dom_node.getElementsByTagName(refname)
    if len(list) > 0:
        for i in list:
            uuids.append(getRef(i))
    return uuids

def get_ost_net(dom_node, uuid):
    ost = lookup(dom_node, uuid)
    uuid = get_first_ref(ost, 'network')
    if not uuid:
        return None
    return lookup(dom_node, uuid)

def nid2server(dom_node, nid):
    netlist = dom_node.getElementsByTagName('network')
    for net_node in netlist:
        if get_text(net_node, 'server') == nid:
            return Network(net_node)
    return None
    
def lookup(dom_node, uuid):
    for n in dom_node.childNodes:
        if n.nodeType == n.ELEMENT_NODE:
            if getUUID(n) == uuid:
                return n
            else:
                n = lookup(n, uuid)
                if n: return n
    return None
            
# Get name attribute of dom_node
def getName(dom_node):
    return dom_node.getAttribute('name')

def getRef(dom_node):
    return dom_node.getAttribute('uuidref')

# Get name attribute of dom_node
def getUUID(dom_node):
    return dom_node.getAttribute('uuid')

# the tag name is the service type
# fixme: this should do some checks to make sure the dom_node is a service
def getServiceType(dom_node):
    return dom_node.nodeName


############################################################
# routing ("rooting")
#
routes = []
local_node = []
router_flag = 0

def init_node(dom_node):
    global local_node, router_flag
    netlist = dom_node.getElementsByTagName('network')
    for dom_net in netlist:
        type = get_attr(dom_net, 'type')
        gw = get_text(dom_net, 'server')
        local_node.append((type, gw))

def node_needs_router():
    return router_flag

def get_routes(type, gw, dom_net):
    """ Return the routes as a list of tuples of the form:
        [(type, gw, lo, hi),]"""
    res = []
    tbl = dom_net.getElementsByTagName('route_tbl')
    for t in tbl:
        routes = t.getElementsByTagName('route')
        for r in routes:
            lo = get_attr(r, 'lo')
            hi = get_attr(r, 'hi', '')
            res.append((type, gw, lo, hi))
    return res
    

def init_route_config(lustre):
    """ Scan the lustre config looking for routers.  Build list of
    routes. """
    global routes, router_flag
    routes = []
    list = lustre.getElementsByTagName('node')
    for node in list:
        if get_attr(node, 'router'):
            router_flag = 1
            for (local_type, local_nid) in local_node:
                gw = None
                netlist = node.getElementsByTagName('network')
                for dom_net in netlist:
                    if local_type == get_attr(dom_net, 'type'):
                        gw = get_text(dom_net, 'server')
                        break
                if not gw:
                    continue
                for dom_net in netlist:
                    if local_type != get_attr(dom_net, 'type'):
                        for route in get_routes(local_type, gw, dom_net):
                            routes.append(route)
    

def local_net(net):
    global local_node
    for iface in local_node:
        if net.net_type == iface[0]:
            return 1
    return 0

def find_route(net):
    global local_node, routes
    frm_type = local_node[0][0]
    to_type = net.net_type
    to = net.nid
    debug ('looking for route to', to_type,to)
    for r in routes:
        if  r[2] == to:
            return r
    return None
           



##############################################################################
# Here it starts LDAP related stuff.

import ldap
import _ldap

#returns the lustre ldap specific filters

class lustre_ldap:
	def __init__(self):
		self.filter=0

	def get_filter(self,lustreRdn):
		filter="(&"+lustreRdn+")"
		return filter

# make a connection to LDAP server and abd bind
class MyConn:
	def __init__(self,host,port):
		self.id=0
		self.host=host
		self.port=port
		self.base="fs=lustre"

	def open(self):
		self.id=ldap.open(self.host)
		if self.id == None:
			print "unable to open a connection"
	
		try:
			# lustre tree starts from here...the DN is (cn=Manager ,fs=lustre)
			status=self.id.simple_bind("cn=Manager, fs=lustre","secret")
		except _ldap.LDAPError:
			print "unable to bind"
		
	

# Lustre Node object class definition as per defined in the lustre.schema			

class LustreNode:
	def __init__(self,nodename):
		self.objectClass="lustreNode"
		self.nodeUUID = 0
		self.id= nodename
		self.netUUIDs = []
		self.profileUUID = 0
		self.routerUUID = 0
		self.ldlmUUID = 0

		self.lustreNet = {}
		self.lustreNodeProfile = 0
		self.lustreLdlm = 0

		self.nodeUUID_str="nodeUUID"
		self.id_str="id"
		self.netUUIDs_str="netUUIDs"
		self.ldlmUUID_str="ldlmUUID"
		self.profileUUID_str="profileUUID"
		self.routerUUID_str="routerUUID"
		self.node_str="node"

	def get_object_class(self):
		return self.objectClass

	def get_rdn(self):
		retval="(objectClass="+self.objectClass+") (id="+self.id+")"
		return retval

	# Initilize lustre Node Object class after read drom LDAP server
	def init_node(self,node_entry):
		self.id=node_entry[0][1][self.id_str][0]
		self.nodeUUID=node_entry[0][1][self.nodeUUID_str][0]
		for i in range(len(node_entry[0][1][self.netUUIDs_str])):
			self.netUUIDs.append(node_entry[0][1][self.netUUIDs_str][i])
		if node_entry[0][1].has_key(self.profileUUID_str):
			self.profileUUID=node_entry[0][1][self.profileUUID_str][0]
		if node_entry[0][1].has_key(self.ldlmUUID_str):
			self.ldlmUUID=node_entry[0][1][self.ldlmUUID_str][0]

		if node_entry[0][1].has_key(self.routerUUID_str):
			self.routerUUID=node_entry[0][1][self.routerUUID_str][0]

	# Brings the lustre Node object entries from LDAP server
	def getEntry_from_ldap(self,conn_id,base):
		try:
			lustre_util=lustre_ldap()
			# the filter has id=<nodename>,type=node,fs=lustre
			# base is "fs=lustre"
			filter=lustre_util.get_filter(self.get_rdn())
			result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
			if result == []:
				print "Error No Results found"
				sys.exit(1)
			self.init_node(result)
			#network object class
			if self.netUUIDs:
				for i in range(len(self.netUUIDs)):
					# loading the network object class from LDAP, since this related to lustre node class
					self.lustreNet[i]=LustreNet()
					self.lustreNet[i].getEntry_from_ldap(conn_id,base,self.netUUIDs[i])

			# The ldlm object class
			if self.ldlmUUID:
				# loading the ldlm object class from LDAP, since this related to lustre node class
				self.lustreLdlm=LustreLdlm()
				self.lustreLdlm.getEntry_from_ldap(conn_id,base,self.ldlmUUID)

			# The lustre node profile object class
			if self.profileUUID:
				# loading the node profile object class from LDAP, since this related to lustre node class
				# The node profile contains the clientUUID, mdsUUIDs (multiple) and ostUUIDs(multiple)
				# the rest of the object class queried from LDAP server useing above UUIDs 
				self.lustreNodeProfile=LustreNodeProfile()
				self.lustreNodeProfile.getEntry_from_ldap(conn_id,base,self.profileUUID)

		except ldap.NO_SUCH_OBJECT:
			print "no results Found"
			exit(1)
			
	def get_dn(self,id):
		return self.id_str+"="+id+",type="+self.node_str+",fs=lustre"

	# add entries into LDAP server, All of them are must fields
	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.id)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.id_str,[self.id]))
		modlist.append((self.nodeUUID_str,[self.nodeUUID]))
		modlist.append((self.netUUIDs_str,self.netUUIDs))
		modlist.append((self.profileUUID_str,[self.profileUUID]))
		modlist.append((self.routerUUID_str,[self.routerUUID]))
		modlist.append((self.ldlmUUID_str,[self.ldlmUUID]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
		return status

        def initobj(self,*args):
		print "init obj :", args
	# print values of object class
	def print_node(self):
		print "lustre Node Attributes......"
		print "objectClass: %s" % self.objectClass
		print "node UUID: %s" % self.nodeUUID
		print "node name: %s" % self.id
		for i in range(len(self.netUUIDs)):
			print "network UUID%d: %s" % (i,self.netUUIDs[i])
		print "Node Profile UUID: %s" % self.profileUUID
		print "Router UUID: %s" % self.routerUUID
		print "Ldlm UUID: %s" % self.ldlmUUID
		print 
		for i in range(len(self.netUUIDs)):
			self.lustreNet[i].print_net()
		
		self.lustreNodeProfile.print_profile()
		self.lustreLdlm.print_ldlm()
		


# lustre Client object class It have mount uuid and net uuid, but the net uuid may not required at present.
class LustreClient:
	def __init__(self,lustreNode):
		self.objectClass="lustreClient"
		self.clientUUID=0
		self.mountUUIDs=[]
		self.netUUID=0

		self.lustreNode=lustreNode
		self.lustreNet= 0
		self.lustreMount={}

	
		self.clientUUID_attr="clientUUID"
		self.mountUUID_attr="mountUUIDs"
		self.netUUID_attr="netUUID"
		self.client_attr="client"
	
	def ge_object_class(self):
		return self.objectClass

	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (clientUUID="+attr_value+")"
		return retval


	# load the object class with client config params
	def init_node(self,node_entry):
		self.clientUUID=node_entry[0][1][self.clientUUID_attr][0]
		for i in range(len(node_entry[0][1][self.mountUUID_attr])):
			self.mountUUIDs.append(node_entry[0][1][self.mountUUID_attr][i])
		self.netUUID=node_entry[0][1][self.netUUID_attr][0]


	# brings the client config params from LDAP, here the search criteria is clientUUID=lustre1_client_UUID,type=client,fs=lustre, this is called as dn
	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		# filter has "clientUUID=lustre1_client_UUID,type=client,fs=lustre"
		# the base is "fs=lustre"
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Client Error No Results found"
			sys.exit(1)

		self.init_node(result)

		if self.netUUID:
			self.lustreNet=LustreNet()
			self.lustreNet.getEntry_from_ldap(conn_id,base,self.netUUID)
		else:
			print "Unable to find the LDLM uuid in Client Object Class..."

		if self.mountUUIDs:
			for mntuuid in self.mountUUIDs:
				self.lustreMount[mntuuid]=LustreMount()
				self.lustreMount[mntuuid].getEntry_from_ldap(conn_id,base,mntuuid)

			
	def get_dn(self,uuid):
		retval=self.clientUUID_attr+"="+uuid+",type="+self.client_attr+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.clientUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.clientUUID_attr,[self.clientUUID]))
		modlist.append((self.mountUUID_attr,self.mountUUIDs))
		modlist.append((self.netUUID_attr,[self.netUUID]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_client(self):
		print "Lustre Client Configurations..............."
		print "client Object Calss: %s" % self.objectClass
		print "client UUID: %s" % self.clientUUID
		print "This client supporting %d file systems" % len(self.mountUUIDs)
		if self.lustreNet:
			self.lustreNet.print_net()

		if self.mountUUIDs:
			for mntuuid in self.mountUUIDs:
				self.lustreMount[mntuuid].print_mount()




class LustreMount:
	def __init__(self):
		self.objectClass="lustreMount"
		self.mountUUID=0
		self.mdsUUID=0
		self.lovUUID=0
		self.mountPath=""
		self.default=0

		self.lustreMds=0
		self.lustreLov=0

		self.mountUUID_attr="mountUUID"
		self.mdsUUID_attr="mdsUUID"
		self.lovUUID_attr="lovUUID"
		self.mountPath_attr="mountPath"
		self.default_attr="default"
		self.type="mountPoint"


	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (mountUUID="+attr_value+")"
		return retval


	def init_node(self,record):
		self.mdsUUID=record[0][1][self.mdsUUID_attr][0]
		self.mountUUID=record[0][1][self.mountUUID_attr][0]
		self.lovUUID=record[0][1][self.lovUUID_attr][0]
		self.mountPath=record[0][1][self.mountPath_attr][0]
		self.default=record[0][1][self.default_attr][0]

	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Mount Error No Results found"
			sys.exit(1)
		self.init_node(result)
		
		if self.mdsUUID:
			self.lustreMds=LustreMds()
			self.lustreMds.getEntry_from_ldap(conn_id,base,self.mdsUUID)

		if self.lovUUID:
			self.lustreLov=LustreLov()
			self.lustreLov.getEntry_from_ldap(conn_id,base,self.lovUUID)
			
	def get_dn(self,uuid):
		retval=self.mountUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.mountUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.mountUUID_attr,[self.mountUUID]))
		modlist.append((self.mdcUUID_attr,self.mdcUUID))
		modlist.append((self.lovUUID_attr,[self.lovUUID]))
		modlist.append((self.mountPath_attr,[self.mountPath]))
		modlist.append((self.default_attr,[self.default]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_mount(self):

				print "Lustre mount point attributes......"
				print "mount object class: %s" % self.objectClass
				print "mount UUID: %s" % self.mountUUID
				print "mds UUID: %s" % self.mdsUUID
				print "lov UUID: %s" % self.lovUUID
				print "mount point: %s" % self.mountPath
				if self.default:
					print "This file system is default file system for this cleint"
				else:
					print "This file system is not a default file system for this cleint"

				if self.lustreMds:
					self.lustreMds.print_mds()
				if self.lustreLov:
					self.lustreLov.print_lov()


class LustreOsc:
	def __init__(self):
		self.objectClass="lustreOSC"
		self.oscUUID=0
		self.devName=""
		self.obdUUID=0
		self.ostUUID=0

		self.lustreObd=0
		self.lustreOst=0

		self.oscUUID_attr="oscUUID"
		self.devName_attr="devName"
		self.obdUUID_attr="obdUUID"
		self.ostUUID_attr="ostUUID"
		self.type="OSC"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (oscUUID="+attr_value+")"
		return retval


	def init_node(self,record):
		self.oscUUID=record[0][1][self.oscUUID_attr][0]
		self.obdUUID=record[0][1][self.obdUUID_attr][0]
		self.ostUUID=record[0][1][self.ostUUID_attr][0]
		self.devName=record[0][1][self.devName_attr][0]


	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)
	
		if self.obdUUID:
			self.lustreObd=LustreObd()
			self.lustreObd.getEntry_from_ldap(conn_id,base,self.obdUUID)

		if self.ostUUID:
			self.lustreOst=LustreOst()
			self.lustreOst.getEntry_from_ldap(conn_id,base,self.ostUUID)

	def get_dn(self,uuid):
		retval=self.oscUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.oscUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.oscUUID_attr,[self.oscUUID]))
		modlist.append((self.devName_attr,self.devName))
		modlist.append((self.obdUUID_attr,[self.obdUUID]))
		modlist.append((self.ostUUID_attr,[self.ostUUID]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_osc(self):
		print "Lustre Osc Attrributes.."
		print "object class: %s" % self.objectClass
                print "oscUUID: %s" % self.oscUUID
                print "devName: %s" % self.devName
                print "obdUUID: %s" % self.obdUUID
                print "ostUUID: %s" % self.ostUUID
		print 
		if self.lustreObd:
			self.lustreObd.print_obd()
		print 
		if self.lustreOst:
			self.lustreOst.print_ost()
		print 


class LustreMdc:
	def __init__(self):
		self.objectClass="lustreMDC"
		self.mdcUUID=0
		self.devName=""
		self.mdsUUID=0

		self.lustreMds=0

		self.mdcUUID_attr="mdcUUID"
		self.devName_attr="devName"
		self.mdsUUID_attr="mdsUUID"
		self.type="MDC"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (mdcUUID="+attr_value+")"
		return retval


	def init_node(self,record):
		self.mdcUUID=record[0][1][self.mdcUUID_attr][0]
		self.mdsUUID=record[0][1][self.mdsUUID_attr][0]
		self.devName=record[0][1][self.devName_attr][0]

	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)

		if self.mdsUUID:
			self.lustreMds=LustreMds()
			self.lustreMds.getEntry_from_ldap(conn_id,base,self.mdsUUID)


	def get_dn(self,uuid):
		retval=self.mdcUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.mdcUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.mdcUUID_attr,[self.mdcUUID]))
		modlist.append((self.devName_attr,self.devName))
		modlist.append((self.mdsUUID_attr,[self.mdsUUID]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_mdc(self):
		print "Lustre Mdc attributes....."
		print "Mdc UUID: %s" % self.mdcUUID
		print "dev name: %s" % self.devName
		print "Mds UUId: %s" % self.mdsUUID
		print
		if self.lustreMds:
			self.lustreMds.print_mds()



class LustreOst:
	def __init__(self):
		self.objectClass="lustreOST"
		self.ostUUID=0
		self.devName=""
		self.obdUUID=0

		self.lustreObd=0

		self.ostUUID_attr="ostUUID"
		self.devName_attr="devName"
		self.obdUUID_attr="obdUUID"
		self.type="OST"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (ostUUID="+attr_value+")"
		return retval

	def init_node(self,record):
		self.ostUUID=record[0][1][self.ostUUID_attr][0]
		self.obdUUID=record[0][1][self.obdUUID_attr][0]
		self.devName=record[0][1][self.devName_attr][0]

	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)

		if self.obdUUID:
			self.lustreObd=LustreObd()
			self.lustreObd.getEntry_from_ldap(conn_id,base,self.obdUUID)
		

	def get_dn(self,uuid):
		retval=self.ostUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.ostUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.ostUUID_attr,[self.ostUUID]))
		modlist.append((self.devName_attr,[self.devName]))
		modlist.append((self.obdUUID_attr,[self.obdUUID]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_ost(self):
		print "Lustre Ost Attributes...."
		print "object class: %s" % self.objectClass
                print "ostUUID: %s" % self.ostUUID
                print "devName: %s" % self.devName
                print "obdUUID: %s" % self.obdUUID
		print
		if self.lustreObd:
			self.lustreObd.print_obd()



class LustreMds:
	def __init__(self):
		self.objectClass="lustreMDS"
		self.mdsUUID=0
		self.devName=""
		self.devUUID=0
		self.lovUUID=0
		self.fUUID=0
		
		self.lustreDev=0
		self.lustreLov=0

		self.mdsUUID_attr="mdsUUID"
		self.devName_attr="devName"
		self.devUUID_attr="devUUID"
		self.lovUUID_attr="lovUUID"
		self.fUUID_attr="fUUID"
		self.type="MDS"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (mdsUUID="+attr_value+")"
		return retval


	def init_node(self,record):
		self.mdsUUID=record[0][1][self.mdsUUID_attr][0]
		self.devUUID=record[0][1][self.devUUID_attr][0]
		self.lovUUID=record[0][1][self.lovUUID_attr][0]
		#self.fUUID=record[0][1][self.fUUID_attr][0]
		self.devName=record[0][1][self.devName_attr][0]

	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)


		if self.devUUID:
			self.lustreDev=LustreDevice()
			self.lustreDev.getEntry_from_ldap(conn_id,base,self.devUUID)

		if self.lovUUID:
			self.lustreLov=LustreLov()
			self.lustreLov.getEntry_from_ldap(conn_id,base,self.lovUUID)


	def get_dn(self,uuid):
		retval=self.mdsUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.mdsUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.mdsUUID_attr,[self.mdsUUID]))
		modlist.append((self.devName_attr,[self.devName]))
		modlist.append((self.devUUID_attr,[self.devUUID]))
		modlist.append((self.lovUUID_attr,[self.lovUUID]))
		modlist.append((self.fUUID_attr,[self.fUUID]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_mds(self):
		print "Lustre Mds Attributes..."
		print "object Class: %s" % self.objectClass
                print "mdsUUID: %s" % self.mdsUUID
                print "devName: %s" % self.devName
                print "devUUID: %s" % self.devUUID
                #print "fUUID: %s" % self.fUUID
                print "lovUUID: %s" % self.lovUUID
		print 
		if self.lustreLov:
		    self.lustreLov.print_lov()
		    print 


class LustreLov:
	def __init__(self):
		self.objectClass="lustreLOV"
		self.lovUUID=0
		self.devName = ""
		self.oscUUIDs= []
		self.stripeOffset=0
		self.stripeSize=0
		self.stripeCount=0
		self.pattern=0

		self.lustreOsc = {}

		self.lovUUID_attr="lovUUID"
		self.devName_attr="devName"
		self.oscUUID_attr="oscUUIDs"
		self.stripeOffset_attr="stripeOffset"
		self.stripeSize_attr="stripeSize"
		self.stripeCount_attr="stripeCount"
		self.pattern_attr="pattern"
		self.type="LOV"

	def get_object_class(self):
		return self.objectCalss



	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (lovUUID="+attr_value+")"
		return retval


	def init_node(self,record):
		nofvals=len(record[0][1][self.oscUUID_attr])
		for i in range(nofvals):
			self.oscUUIDs.append(record[0][1][self.oscUUID_attr][i])

		self.stripeOffset=record[0][1][self.stripeOffset_attr][0]
		self.lovUUID=record[0][1][self.lovUUID_attr][0]
		self.devName = record[0][1][self.devName_attr][0]
		self.stripeSize=record[0][1][self.stripeSize_attr][0]
		self.stripeCount=record[0][1][self.stripeCount_attr][0]
		self.pattern=record[0][1][self.pattern_attr][0]

	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)


		if self.oscUUIDs:
			for uuid in self.oscUUIDs:
				self.lustreOsc[uuid]=LustreOsc()
				self.lustreOsc[uuid].getEntry_from_ldap(conn_id,base,uuid)

	def get_dn(self,uuid):
		retval=self.lovUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.lovUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.lovUUID_attr,[self.lovUUID]))
		modlist.append((self.devName_attr,[self.devName]))
		modlist.append((self.oscUUID_attr,self.oscUUIDs))
		modlist.append((self.stripeOffset_attr,[self.stripeOffset]))
		modlist.append((self.stripeSize_attr,[self.stripeSize]))
		modlist.append((self.stripeCount_attr,[self.stripeCount]))
		modlist.append((self.pattern_attr,[self.pattern]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_lov(self):
		print "Lustre LOV attributes..."
		print "object class: %s" % self.objectClass
                print "lovUUID: %s" % self.lovUUID
                print "devName: %s" % self.devName
                print "oscUUIDs are"
		for i in range(len(self.oscUUIDs)):
			print "oscUUID[%d]: %s" % (i,self.oscUUIDs[i])
                print "stripeOffset: %s" % self.stripeOffset
                print "stripe Size: %s" % self.stripeSize
                print "stripe Count: %s" % self.stripeCount
                print "pattern: %s" % self.pattern
		
		print 
		if self.oscUUIDs:
			for uuid in self.oscUUIDs:
				if self.lustreOsc:
				    self.lustreOsc[uuid].print_osc()
		print 


class LustreDevice:
	def __init__(self):
		self.objectClass="lustreDevice"
		self.id=""
		self.fid=""
		self.devUUID=0
		self.netUUID=0
		self.fnetUUID=0
		self.device=""
		self.auto=0
		self.fsType=""
		self.size=0

		self.id_attr="id"
		self.fid_attr="fid"
		self.devUUID_attr="devUUID"
		self.netUUID_attr="netUUID"
		self.fnetUUID_attr="fnetUUID"
		self.device_attr="device"
		self.auto_attr="auto"
		self.fsType_attr="fsType"
		self.size_attr="size"
		self.type="device"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (devUUID="+attr_value+")"
		return retval

	def init_node(self,record):
		self.devUUID=record[0][1][self.devUUID_attr][0]
		self.netUUID=record[0][1][self.netUUID_attr][0]
		self.fnetUUID=record[0][1][self.fnetUUID_attr][0]
		self.id=record[0][1][self.id_attr][0]
		self.fid=record[0][1][self.fid_attr][0]
		self.device=record[0][1][self.device_attr][0]
		self.auto=record[0][1][self.auto_attr][0]
		self.fsType=record[0][1][self.fsType_attr][0]
		self.size=record[0][1][self.size_attr][0]

	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)

	def get_dn(self,uuid):
		retval=self.devUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.devUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.devUUID_attr,[self.devUUID]))
		modlist.append((self.netUUID_attr,[self.netUUID]))
		modlist.append((self.fnetUUID_attr,[self.fnetUUID]))
		modlist.append((self.id_attr,[self.id]))
		modlist.append((self.fid_attr,[self.fid]))
		modlist.append((self.device_attr,self.device))
		modlist.append((self.auto_attr,[self.auto]))
		modlist.append((self.fsType_attr,[self.fsType]))
		modlist.append((self.size_attr,[self.size]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_device(self):
                print "lustre Device object...."
		print "object Calss: %s" % self.objectClass
                print "node name: %s" % self.id
                print "failover node name: %s" % self.fid
                print "devUUID: %s" % self.devUUID
                print "netUUID: %s" % self.netUUID
                print "failover netUUID: %s" % self.fnetUUID
                print "device: %s" % self.device
                print "autoformat: %s" % self.auto
                print "fs type: %s" % self.fsType
                print "size of device: %s" % self.size



class LustreObd:
	def __init__(self):
		self.objectClass="lustreOBD"
		self.obdUUID=0
		self.devName=""
		self.devUUID=0
		self.fUUID=0

		self.lustreDev = 0

		self.obdUUID_attr="obdUUID"
		self.devName_attr="devName"
		self.devUUID_attr="devUUID"
		self.fUUID_attr="fUUID"
		self.type="OBD"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (obdUUID="+attr_value+")"
		return retval

	def init_node(self,record):
		self.obdUUID=record[0][1][self.obdUUID_attr][0]
		self.devName=record[0][1][self.devName_attr][0]
		self.devUUID=record[0][1][self.devUUID_attr][0]
		self.fUUID=record[0][1][self.fUUID_attr][0]

	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)

		if self.devUUID:
			self.lustreDev=LustreDevice()
			self.lustreDev.getEntry_from_ldap(conn_id,base,self.devUUID)


	def get_dn(self,uuid):
		retval=self.obdUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.obdUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.obdUUID_attr,[self.obdUUID]))
		modlist.append((self.devName_attr,[self.devName]))
		modlist.append((self.devUUID_attr,[self.devUUID]))
		modlist.append((self.fUUID_attr,[self.fUUID]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_obd(self):
		print "Lustre Obd attributes...."
		print "object Class: %s" % self.objectClass
                print "obdUUID: %s" % self.obdUUID
                print "devName: %s" % self.devName
                print "devUUID: %s" % self.devUUID
                print "fUUID: %s" % self.fUUID
		print 
		if self.lustreDev:
			self.lustreDev.print_device()
		print 


class LustreLdlm:
	def __init__(self):
		self.objectClass="lustreLDLM"
		self.ldlmUUID=0
		self.devName=""

		self.ldlmUUID_attr="ldlmUUID"
		self.devName_attr="devName"
		self.type="LDLM"

	def get_object_class(self):
		return self.objectCalss


	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (ldlmUUID="+attr_value+")"
		return retval

	def init_node(self,record):
		self.ldlmUUID=record[0][1][self.ldlmUUID_attr][0]
		self.devName=record[0][1][self.devName_attr][0]

	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)


	def get_dn(self,uuid):
		retval=self.ldlmUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id):
		modlist=[]
		dn=self.get_dn(self.ldlmUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.ldlmUUID_attr,[self.ldlmUUID]))
		modlist.append((self.devName_attr,[self.devName]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_ldlm(self):
		print "Printing LDLM attributes..........."
		print "ldlm Object Class: %s" % self.objectClass
		print "ldlm UUID: %s" % self.ldlmUUID
		print "ldlm Name: %s" % self.devName
		print "\n" * 5
		

class LustreNet:
	def __init__(self):
		self.objectClass="lustreNetwork"
		self.netUUID=0
		self.id=0
		self.fnetUUID=0
		self.netType=""
		self.netAddress=""
		self.port=0
		self.recvMem=0
		self.sendMem=0

		self.netUUID_attr="netUUID"
		self.fnetUUID_attr="fnetUUID"
		self.id_attr="id"
		self.netType_attr="netType"
		self.netAddress_attr="netAddress"
		self.port_attr="port"
		self.recvMem_attr="recvMem"
		self.sendMem_attr="sendMem"
		self.type="net"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (netUUID="+attr_value+")"
		return retval

	def init_node(self,record):
		self.netUUID=record[0][1][self.netUUID_attr][0]
		self.fnetUUID=record[0][1][self.fnetUUID_attr][0]
		self.id=record[0][1][self.id_attr][0]
		self.netType=record[0][1][self.netType_attr][0]
		self.netAddress=record[0][1][self.netAddress_attr][0]
		self.port=record[0][1][self.port_attr][0]
		self.recvMem=record[0][1][self.recvMem_attr][0]
		self.sendMem=record[0][1][self.sendMem_attr][0]

	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)


	def get_dn(self,uuid):
		retval=self.netUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id,id,fnetUUID,netUUID,netType,netAddress,port,recvMem,sendMem):
		modlist=[]
		dn=self.get_dn(netUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.netUUID_attr,[netUUID]))
		modlist.append((self.fnetUUID_attr,[fnetUUID]))
		modlist.append((self.id_attr,[id]))
		modlist.append((self.netType_attr,[netType]))
		modlist.append((self.netAddress_attr,[netAddress]))
		modlist.append((self.port_attr,[port]))
		modlist.append((self.recvMem_attr,[recvMem]))
		modlist.append((self.sendMem_attr,[sendMem]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_net(self):
		print "Lustre Network Attributes:......"
		print "object Class: %s" % self.objectClass
		print "network UUID: %s" % self.netUUID
		print "failover network UUID: %s" % self.fnetUUID
		print "node name : %s" % self.id
		print "network Type: %s" % self.netType
		print "IP Address: %s" % self.netAddress
		print "port: %s" % self.port
		print "receive memory: %s" % self.recvMem
		print "send memory: %s" % self.sendMem
		print 
		

class LustreNodeProfile:
	def __init__(self):
		self.objectClass="lustreNodeProfile"
		self.profileUUID=0
		self.mdsUUIDs=[]
		self.ostUUIDs=[]
		self.clientUUID=0

		self.profileUUID_str="profileUUID"
		self.mdsUUIDs_str="mdsUUIDs"
		self.ostUUIDs_str="ostUUIDs"
		self.clientUUID_str="clientUUID"
		self.type="profile"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval="(objectClass="+self.objectClass+") (profileUUID="+attr_value+")"
		return retval

	def init_node(self,node_entry):
		self.profileUUID=node_entry[0][1][self.profileUUID_str][0]
		if node_entry[0][1].has_key(self.mdsUUIDs_str):
			for i in range(len(node_entry[0][1][self.mdsUUIDs_str])):
				self.mdsUUIDs.append(node_entry[0][1][self.mdsUUIDs_str][i])

		if node_entry[0][1].has_key(self.ostUUIDs_str):
			for i in range(len(node_entry[0][1][self.ostUUIDs_str])):
				self.ostUUIDs.append(node_entry[0][1][self.ostUUIDs_str][i])

		if node_entry[0][1].has_key(self.clientUUID_str):
			self.clientUUID=node_entry[0][1][self.clientUUID_str][0]

	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util=lustre_ldap()
		filter=lustre_util.get_filter(self.get_rdn(attr_val))
		result=conn_id.search_s(base,ldap.SCOPE_SUBTREE,filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)

	def get_dn(self,uuid):
		retval=self.profileUUID_str+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id,profileUUID,mdsUUIDs,ostUUIDs,clientUUID):
		modlist=[]
		dn=self.get_dn(profileUUID)
		modlist.append(("objectClass",[self.objectClass]))
		modlist.append((self.profileUUID_str,[profileUUID]))
		modlist.append((self.mdsUUIDs_str,mdsUUIDs))
		modlist.append((self.ostUUIDs_str,ostUUIDs))
		modlist.append((self.clientUUID_str,[clientUUID]))
		modlist.append(("fs",["lustre"]))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			sys.exit(1)
		return status

        def initobj(self,*args):
		print "init obj :", args

	def print_profile(self):
		print "Lustre Node Profile Attributes:......"
		print "object Class: %s" % self.objectClass
		print "profile UUID: %s" % self.profileUUID
		print "This node supports %d mds servers:" % len(self.mdsUUIDs)
		for i in range(len(self.mdsUUIDs)):
			print "Mds UUID%d: %s" % (i,self.mdsUUIDs[i])
		print "This node supports %d ost servers:" % len(self.ostUUIDs)
		for i in range(len(self.ostUUIDs)):
			print "Ost UUID%d: %s" % (i,self.ostUUIDs[i])
		print "Client UUID: %s" % self.clientUUID
		print


def get_matched_osc(ConnId,ostuuid):
    result = ConnId.search_s("fs=lustre",ldap.SCOPE_SUBTREE,"objectclass=lustreOSC")
    lustreOSC = 0
    if result:
       for i in range(len(result)):
	   tmpuuid = result[i][1]['ostUUID'][0]
	   if ostuuid == tmpuuid:
	       lustreOSC = LustreOsc()
	       lustreOSC.init_node([result[i]])
	       break

    else:
	   print "no result"

    return lustreOSC


def get_matched_lov(ConnId,oscuuid): 
    print "inside.. get matched lov:", oscuuid
    result = ConnId.search_s("fs=lustre",ldap.SCOPE_SUBTREE,"objectclass=lustreLOV")
    lustreLOV = 0
    tmpuuids = []
    if result:
       for i in range(len(result)):
           tmpuuids = result[i][1]['oscUUIDs']
	   for uuid in tmpuuids:
	   	if oscuuid == uuid:
		   lustreLOV = LustreLov()
		   lustreLOV.init_node([result[i]])
		   return lustreLOV
    return 0
			



