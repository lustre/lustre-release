#!/usr/bin/env python
#
#   Author: Ravindranadh Chowdary Sahukara <s-ravindranadh.chowdary@hp.com>
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

from types import DictType, ListType, TupleType, StringType
import string, os, stat, popen2, socket, time, random
import sys, getopt
import re, exceptions
import xml.dom.minidom
from sys import exit
from string import split,join


# Global parameters
DEFAULT_TCPBUF = 0


def panic(*args):
    msg = string.join(map(str,args))
    print "! " + msg
    exit(1)

def debug(*args):
    msg = string.join(map(str,args))
    print msg


names = {}
uuids = {}


def new_name(bas):
    ctr = 2
    ret = bas
    while names.has_key(ret):
        ret = "%s_%d" % (bas, ctr)
        ctr = 1 + ctr
    names[ret] = 1
    return str(ret)

def new_uuid(name):
    return "%s_UUID" % (name)

        
def getServices(lustreNode, profileNode):
    list = []
    for n in profileNode.childNodes:
        if n.nodeType == n.ELEMENT_NODE:
            servNode = lookup(lustreNode, getRef(n))
            if not servNode:
                print n
                panic('service not found: ' + getRef(n))
            list.append((servNode))
    #list.sort()
    return list

def getByName(lustreNode, name, tag):
    ndList = lustreNode.getElementsByTagName(tag)
    for nd in ndList:
        if getName(nd) == name:
            return nd
    return None
    


class Module:
    """ Base class for the rest of the modules.  """
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
        """ Lookup a servers network information """
        net = get_ost_net(self.dom_node.parentNode, srv_uuid)
        if not net:
            panic ("Unable to find a server for:", srv_uuid)
        self._server = Network(net)

    def get_server(self):
        return self._server


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


class LDLM(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'LDLM', dom_node)

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

class LOVConfig(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'LOVConfig', dom_node)
        self.lov_uuid = get_first_ref(dom_node, 'lov')
        l = lookup(dom_node.parentNode, self.lov_uuid)
        self.lov = LOV(l)
        

class MDS(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'MDS', dom_node)
        self.devname, self.size = get_device(dom_node)
        self.fstype = get_text(dom_node, 'fstype')
        # FIXME: if fstype not set, then determine based on kernel version
        self.format = get_text(dom_node, 'autoformat', "no")
        self.lookup_server(self.uuid)

# Very unusual case, as there is no MDC element in the XML anymore
# Builds itself from an MDS node
class OBD(Module):
    def __init__(self, dom_node):
        Module.__init__(self, 'OBD', dom_node)
        self.obdtype = get_attr(dom_node, 'type')
        self.devname, self.size = get_device(dom_node)
        self.fstype = get_text(dom_node, 'fstype')
        # FIXME: if fstype not set, then determine based on kernel version
        self.format = get_text(dom_node, 'autoformat', 'yes')

class OST(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'OST', dom_node)
        self.obd_uuid = get_first_ref(dom_node, 'obd')


# virtual interface for  OSC and LOV
class VOSC(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'VOSC', dom_node)
        if dom_node.nodeName == 'lov':
            self.osc = LOV(dom_node)
        else:
            self.osc = OSC(dom_node)

class OSC(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'OSC', dom_node)
        self.obd_uuid = get_first_ref(dom_node, 'obd')
        self.ost_uuid = get_first_ref(dom_node, 'ost')
        self.lookup_server(self.ost_uuid)

class Mountpoint(Module):
    def __init__(self,dom_node):
        Module.__init__(self, 'MTPT', dom_node)
        self.path = get_text(dom_node, 'path')
        self.mds_uuid = get_first_ref(dom_node, 'mds')
        self.lov_uuid = get_first_ref(dom_node, 'osc')
        l = lookup(self.dom_node.parentNode, self.lov_uuid)
        self.osc = VOSC(l)

# ============================================================

def get_device(obd):
    list = obd.getElementsByTagName('device')
    if len(list) > 0:
        dev = list[0]
        dev.normalize();
        size = get_attr_int(dev, 'size', 0)
        return str(dev.firstChild.data), str(size)
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
        return str(v)
    return str(default)

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
    return str(dom_node.getAttribute('name'))

def getRef(dom_node):
    return dom_node.getAttribute('uuidref')

# Get name attribute of dom_node
def getUUID(dom_node):
    return str(dom_node.getAttribute('uuid'))

# the tag name is the service type
def getServiceType(dom_node):
    return dom_node.nodeName



##############################################################################
# LDAP related stuff tarts here...

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
		self.id = 0
		self.host = host
		self.port = port
		self.base = "fs=lustre"

	def open(self):
		self.id = ldap.open(self.host)
		if self.id == None:
			print "unable to open a connection"
	
		try:
			# lustre tree starts from here...the DN is (cn=Manager ,fs=lustre)
			status = self.id.simple_bind("cn=Manager, fs=lustre","secret")
		except _ldap.LDAPError:
			print "unable to bind"
		
	

# Lustre Node object class definition as per defined in the lustre.schema

class LustreNode:
	def __init__(self, nodename):
		self.objectClass = "lustreNode"
		self.nodeUUID = 0
		self.id = nodename
		self.netUUIDs = []
		self.profileUUID = 0
		self.routerUUID = 0
		self.ldlmUUID = 0

		self.lustreNet = {}
		self.lustreNodeProfile = 0
		self.lustreLdlm = 0

		self.nodeUUID_str = "nodeUUID"
		self.id_str = "id"
		self.netUUIDs_str = "netUUIDs"
		self.ldlmUUID_str = "ldlmUUID"
		self.profileUUID_str = "profileUUID"
		self.routerUUID_str = "routerUUID"
		self.node_str = "node"

	def get_object_class(self):
		return self.objectClass

	def get_rdn(self):
		retval = "(objectClass="+self.objectClass+") (id="+self.id+")"
		return retval

	# Initilize lustre Node Object class after read drom LDAP server
	def init_node(self, node_entry):
		self.id = node_entry[0][1][self.id_str][0]
		self.nodeUUID = node_entry[0][1][self.nodeUUID_str][0]
		for i in range(len(node_entry[0][1][self.netUUIDs_str])):
			self.netUUIDs.append(node_entry[0][1][self.netUUIDs_str][i])
		if node_entry[0][1].has_key(self.profileUUID_str):
			self.profileUUID = node_entry[0][1][self.profileUUID_str][0]
		if node_entry[0][1].has_key(self.ldlmUUID_str):
			self.ldlmUUID = node_entry[0][1][self.ldlmUUID_str][0]

		if node_entry[0][1].has_key(self.routerUUID_str):
			self.routerUUID = node_entry[0][1][self.routerUUID_str][0]

	# Brings the lustre Node object entries from LDAP server
	def getEntry_from_ldap(self, conn_id, base):
		try:
			lustre_util = lustre_ldap()
			# the filter has id=<nodename>,type=node,fs=lustre
			# base is "fs=lustre"
			filter = lustre_util.get_filter(self.get_rdn())
			result = conn_id.search_s(base, ldap.SCOPE_SUBTREE, filter)
			if result == []:
				print "Error No Results found"
				sys.exit(1)
			self.init_node(result)
			#network object class
			if self.netUUIDs:
				for netuuid in self.netUUIDs:
					# loading the network object class from LDAP, since this related to lustre node class
					self.lustreNet[netuuid] = LustreNet()
					self.lustreNet[netuuid].getEntry_from_ldap(conn_id, base, netuuid)

			# The ldlm object class
			if self.ldlmUUID:
				# loading the ldlm object class from LDAP, since this related to lustre node class
				self.lustreLdlm = LustreLdlm()
				self.lustreLdlm.getEntry_from_ldap(conn_id, base, self.ldlmUUID)

			# The lustre node profile object class
			if self.profileUUID:
				# loading the node profile object class from LDAP, since this related to lustre node class
				# The node profile contains the clientUUID, mdsUUIDs (multiple) and ostUUIDs(multiple)
				# the rest of the object class queried from LDAP server useing above UUIDs 
				self.lustreNodeProfile = LustreNodeProfile()
				self.lustreNodeProfile.getEntry_from_ldap(conn_id, base, self.profileUUID)

		except ldap.NO_SUCH_OBJECT:
			print "no results Found"
			exit(1)
			
	def get_dn(self,id):
		return self.id_str+"="+id+",type="+self.node_str+",fs=lustre"

	# add entries into LDAP server, All of them are must fields
	def addEntry_into_ldap(self, conn_id, id, nodeUUID, netUUIDs, profileUUID, routerUUID, ldlmUUID):
		modlist = []
		dn = self.get_dn(self.id)
		modlist.append(("objectClass", [self.objectClass]))
		modlist.append((self.id_str, id))
		modlist.append((self.nodeUUID_str, nodeUUID))
		modlist.append((self.netUUIDs_str, netUUIDs))
		modlist.append((self.profileUUID_str, profileUUID))
		modlist.append((self.routerUUID_str, routerUUID))
		modlist.append((self.ldlmUUID_str, ldlmUUID))
		modlist.append(("fs", ["lustre"]))
		status = 0
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
		self.objectClass = "lustreClient"
		self.clientUUID = 0
		self.mountUUIDs = []
		self.netUUID = 0

		self.lustreNode = lustreNode
		self.lustreNet = 0
		self.lustreMount = {}

	
		self.clientUUID_attr = "clientUUID"
		self.mountUUID_attr = "mountUUIDs"
		self.netUUID_attr = "netUUID"
		self.client_attr = "client"
	
	def ge_object_class(self):
		return self.objectClass

	def get_rdn(self,attr_value):
		retval = "(objectClass="+self.objectClass+") (clientUUID="+attr_value+")"
		return retval


	# load the object class with client config params
	def init_node(self,node_entry):
		self.clientUUID = node_entry[0][1][self.clientUUID_attr][0]
		for i in range(len(node_entry[0][1][self.mountUUID_attr])):
			self.mountUUIDs.append(node_entry[0][1][self.mountUUID_attr][i])
		self.netUUID = node_entry[0][1][self.netUUID_attr][0]


	# brings the client config params from LDAP, here the search criteria is clientUUID=lustre1_client_UUID,type=client,fs=lustre, this is called as dn
	def getEntry_from_ldap(self,conn_id,base,attr_val):
		lustre_util = lustre_ldap()
		# filter has "clientUUID=lustre1_client_UUID,type=client,fs=lustre"
		# the base is "fs=lustre"
		filter = lustre_util.get_filter(self.get_rdn(attr_val))
		result = conn_id.search_s(base, ldap.SCOPE_SUBTREE, filter)
		if result == []:
			print "Client Error No Results found"
			sys.exit(1)

		self.init_node(result)

		if self.netUUID:
			self.lustreNet = LustreNet()
			self.lustreNet.getEntry_from_ldap(conn_id, base, self.netUUID)
		else:
			print "Unable to find the LDLM uuid in Client Object Class..."

		if self.mountUUIDs:
			for mntuuid in self.mountUUIDs:
				self.lustreMount[mntuuid] = LustreMount()
				self.lustreMount[mntuuid].getEntry_from_ldap(conn_id, base, mntuuid)

			
	def get_dn(self, uuid):
		retval = self.clientUUID_attr+"="+uuid+",type="+self.client_attr+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id, clientUUID, mountUUIDs, netUUID):
		modlist = []
		dn = self.get_dn(clientUUID)
		modlist.append(("objectClass", [self.objectClass]))
		modlist.append((self.clientUUID_attr, clientUUID))
		modlist.append((self.mountUUID_attr, mountUUIDs))
		modlist.append((self.netUUID_attr, netUUID[0]))
		modlist.append(("fs", ["lustre"]))
		status = 0
		try:
			conn_id.add_s(dn, modlist)
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
		self.objectClass = "lustreMount"
		self.mountUUID = 0
		self.mdsUUID = 0
		self.lovUUID = 0
		self.mountPath = ""
		self.default = 0

		self.lustreMds = 0
		self.lustreLov = 0

		self.mountUUID_attr = "mountUUID"
		self.mdsUUID_attr = "mdsUUID"
		self.lovUUID_attr = "lovUUID"
		self.mountPath_attr = "mountPath"
		self.default_attr = "default"
		self.type = "mountPoint"


	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self, attr_value):
		retval = "(objectClass="+self.objectClass+") (mountUUID="+attr_value+")"
		return retval


	def init_node(self, record):
		self.mdsUUID = record[0][1][self.mdsUUID_attr][0]
		self.mountUUID = record[0][1][self.mountUUID_attr][0]
		self.lovUUID = record[0][1][self.lovUUID_attr][0]
		self.mountPath = record[0][1][self.mountPath_attr][0]
		self.default = record[0][1][self.default_attr][0]

	def getEntry_from_ldap(self, conn_id, base, attr_val):
		lustre_util = lustre_ldap()
		filter = lustre_util.get_filter(self.get_rdn(attr_val))
		result = conn_id.search_s(base, ldap.SCOPE_SUBTREE, filter)
		if result == []:
			print "Mount Error No Results found"
			sys.exit(1)
		self.init_node(result)
		
		if self.mdsUUID:
			self.lustreMds = LustreMds()
			self.lustreMds.getEntry_from_ldap(conn_id, base, self.mdsUUID)

		if self.lovUUID:
			self.lustreLov = LustreLov()
			self.lustreLov.getEntry_from_ldap(conn_id, base, self.lovUUID)
			
	def get_dn(self, uuid):
		retval = self.mountUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self, conn_id, mountUUID, mdsUUID, lovUUID, mountPath, default = 0):
		modlist = []
		dn=self.get_dn(mountUUID)
		modlist.append(("objectClass", [self.objectClass]))
		modlist.append((self.mountUUID_attr, mountUUID))
		modlist.append((self.mdsUUID_attr, mdsUUID))
		modlist.append((self.lovUUID_attr, lovUUID))
		modlist.append((self.mountPath_attr, mountPath))
		modlist.append((self.default_attr, default))
		modlist.append(("fs", ["lustre"]))
		status = 0
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
		self.objectClass = "lustreOSC"
		self.oscUUID = 0
		self.devName = ""
		self.obdUUID = 0
		self.ostUUID = 0

		self.lustreObd = 0
		self.lustreOst = 0

		self.oscUUID_attr = "oscUUID"
		self.devName_attr = "devName"
		self.obdUUID_attr = "obdUUID"
		self.ostUUID_attr = "ostUUID"
		self.type = "OSC"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self, attr_value):
		retval = "(objectClass="+self.objectClass+") (oscUUID="+attr_value+")"
		return retval


	def init_node(self, record):
		self.oscUUID=record[0][1][self.oscUUID_attr][0]
		self.obdUUID=record[0][1][self.obdUUID_attr][0]
		self.ostUUID=record[0][1][self.ostUUID_attr][0]
		self.devName=record[0][1][self.devName_attr][0]


	def getEntry_from_ldap(self, conn_id, base, attr_val):
		lustre_util = lustre_ldap()
		filter = lustre_util.get_filter(self.get_rdn(attr_val))
		result = conn_id.search_s(base, ldap.SCOPE_SUBTREE, filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)
	
		if self.obdUUID:
			self.lustreObd = LustreObd()
			self.lustreObd.getEntry_from_ldap(conn_id, base, self.obdUUID)

		if self.ostUUID:
			self.lustreOst = LustreOst()
			self.lustreOst.getEntry_from_ldap(conn_id, base, self.ostUUID)

	def get_dn(self, uuid):
		retval = self.oscUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self, conn_id, oscUUID, devName, obdUUID, ostUUID):
		modlist = []
		dn=self.get_dn(oscUUID)
		modlist.append(("objectClass", [self.objectClass]))
		modlist.append((self.oscUUID_attr, oscUUID))
		modlist.append((self.devName_attr, devName))
		modlist.append((self.obdUUID_attr, obdUUID))
		modlist.append((self.ostUUID_attr, ostUUID))
		modlist.append(("fs", ["lustre"]))
		status = 0
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
		self.objectClass = "lustreOST"
		self.ostUUID = 0
		self.devName = ""
		self.obdUUID = 0

		self.lustreObd = 0

		self.ostUUID_attr = "ostUUID"
		self.devName_attr = "devName"
		self.obdUUID_attr = "obdUUID"
		self.type = "OST"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval = "(objectClass="+self.objectClass+") (ostUUID="+attr_value+")"
		return retval

	def init_node(self, record):
		self.ostUUID = record[0][1][self.ostUUID_attr][0]
		self.obdUUID = record[0][1][self.obdUUID_attr][0]
		self.devName = record[0][1][self.devName_attr][0]

	def getEntry_from_ldap(self, conn_id, base, attr_val):
		lustre_util = lustre_ldap()
		filter = lustre_util.get_filter(self.get_rdn(attr_val))
		result = conn_id.search_s(base, ldap.SCOPE_SUBTREE, filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)

		if self.obdUUID:
			self.lustreObd = LustreObd()
			self.lustreObd.getEntry_from_ldap(conn_id, base, self.obdUUID)
		

	def get_dn(self,uuid):
		retval = self.ostUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self, conn_id, ostUUID, devName, obdUUID):
		modlist = []
		dn=self.get_dn(ostUUID)
		modlist.append(("objectClass", [self.objectClass]))
		modlist.append((self.ostUUID_attr, ostUUID))
		modlist.append((self.devName_attr, devName))
		modlist.append((self.obdUUID_attr, obdUUID))
		modlist.append(("fs", ["lustre"]))
		status=0
		try:
			conn_id.add_s(dn, modlist)
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
		self.objectClass = "lustreMDS"
		self.mdsUUID = 0
		self.devName = ""
		self.devUUID = 0
		self.lovUUID = 0
		self.fUUID = 0
		
		self.lustreDev = 0
		self.lustreLov = 0

		self.mdsUUID_attr = "mdsUUID"
		self.devName_attr = "devName"
		self.devUUID_attr = "devUUID"
		self.lovUUID_attr = "lovUUID"
		self.fUUID_attr = "fUUID"
		self.type = "MDS"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self, attr_value):
		retval = "(objectClass="+self.objectClass+") (mdsUUID="+attr_value+")"
		return retval


	def init_node(self,record):
		self.mdsUUID = record[0][1][self.mdsUUID_attr][0]
		self.devUUID = record[0][1][self.devUUID_attr][0]
		self.lovUUID = record[0][1][self.lovUUID_attr][0]
		#self.fUUID = record[0][1][self.fUUID_attr][0]
		self.devName = record[0][1][self.devName_attr][0]

	def getEntry_from_ldap(self, conn_id, base, attr_val):
		lustre_util = lustre_ldap()
		filter = lustre_util.get_filter(self.get_rdn(attr_val))
		result = conn_id.search_s(base, ldap.SCOPE_SUBTREE, filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)


		if self.devUUID:
			self.lustreDev = LustreDevice()
			self.lustreDev.getEntry_from_ldap(conn_id, base, self.devUUID)

		if self.lovUUID:
			self.lustreLov = LustreLov()
			self.lustreLov.getEntry_from_ldap(conn_id, base, self.lovUUID)


	def get_dn(self, uuid):
		retval = self.mdsUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self, conn_id, mdsUUID, devName, devUUID, lovUUID, fUUID):
		modlist = []
		dn = self.get_dn(mdsUUID)
		modlist.append(("objectClass", [self.objectClass]))
		modlist.append((self.mdsUUID_attr, mdsUUID))
		modlist.append((self.devName_attr, devName))
		modlist.append((self.devUUID_attr, devUUID))
                if lovUUID:
		    modlist.append((self.lovUUID_attr, lovUUID))
		modlist.append((self.fUUID_attr, fUUID))
		modlist.append(("fs", ["lustre"]))
		status = 0

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
		self.objectClass = "lustreLOV"
		self.lovUUID = 0
		self.devName = ""
		self.oscUUIDs = []
		self.stripeOffset = 0
		self.stripeSize = 0
		self.stripeCount = 0
		self.pattern = 0

		self.lustreOsc = {}

		self.lovUUID_attr = "lovUUID"
		self.devName_attr = "devName"
		self.oscUUID_attr = "oscUUIDs"
		self.stripeOffset_attr = "stripeOffset"
		self.stripeSize_attr = "stripeSize"
		self.stripeCount_attr = "stripeCount"
		self.pattern_attr = "pattern"
		self.type = "LOV"

	def get_object_class(self):
		return self.objectCalss



	def get_rdn(self,attr_value):
		retval = "(objectClass="+self.objectClass+") (lovUUID="+attr_value+")"
		return retval


	def init_node(self, record):
		nofvals = len(record[0][1][self.oscUUID_attr])
		for i in range(nofvals):
			self.oscUUIDs.append(record[0][1][self.oscUUID_attr][i])

		self.stripeOffset = record[0][1][self.stripeOffset_attr][0]
		self.lovUUID = record[0][1][self.lovUUID_attr][0]
		self.devName = record[0][1][self.devName_attr][0]
		self.stripeSize = record[0][1][self.stripeSize_attr][0]
		self.stripeCount = record[0][1][self.stripeCount_attr][0]
		self.pattern = record[0][1][self.pattern_attr][0]

	def getEntry_from_ldap(self, conn_id, base, attr_val):
		lustre_util = lustre_ldap()
		filter = lustre_util.get_filter(self.get_rdn(attr_val))
		result = conn_id.search_s(base, ldap.SCOPE_SUBTREE, filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)


		if self.oscUUIDs:
			for uuid in self.oscUUIDs:
				self.lustreOsc[uuid] = LustreOsc()
				self.lustreOsc[uuid].getEntry_from_ldap(conn_id, base, uuid)

	def get_dn(self,uuid):
		retval = self.lovUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self, conn_id, lovUUID, devName, oscUUIDs, stripeOffset, stripeSize, stripeCount, pattern):
		modlist = []
		dn=self.get_dn(lovUUID)
		modlist.append(("objectClass", [self.objectClass]))
		modlist.append((self.lovUUID_attr, lovUUID))
		modlist.append((self.devName_attr, devName))
		modlist.append((self.oscUUID_attr, oscUUIDs))
		modlist.append((self.stripeOffset_attr, stripeOffset))
		modlist.append((self.stripeSize_attr, stripeSize))
		modlist.append((self.stripeCount_attr, stripeCount))
		modlist.append((self.pattern_attr, pattern))
		modlist.append(("fs", ["lustre"]))
		status = 0
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
		self.objectClass = "lustreDevice"
		self.id = ""
		self.fid = ""
		self.devUUID = 0
		self.netUUID = 0
		self.fnetUUID = 0
		self.device = ""
		self.auto = 0
		self.fsType = ""
		self.size = 0

		self.id_attr = "id"
		self.fid_attr = "fid"
		self.devUUID_attr = "devUUID"
		self.netUUID_attr = "netUUID"
		self.fnetUUID_attr = "fnetUUID"
		self.device_attr = "device"
		self.auto_attr = "auto"
		self.fsType_attr = "fsType"
		self.size_attr = "size"
		self.type = "device"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self, attr_value):
		retval = "(objectClass="+self.objectClass+") (devUUID="+attr_value+")"
		return retval

	def init_node(self, record):
		self.devUUID = record[0][1][self.devUUID_attr][0]
		self.netUUID = record[0][1][self.netUUID_attr][0]
		self.fnetUUID = record[0][1][self.fnetUUID_attr][0]
		self.id = record[0][1][self.id_attr][0]
		self.fid = record[0][1][self.fid_attr][0]
		self.device = record[0][1][self.device_attr][0]
		self.auto = record[0][1][self.auto_attr][0]
		self.fsType = record[0][1][self.fsType_attr][0]
		self.size = record[0][1][self.size_attr][0]

	def getEntry_from_ldap(self, conn_id, base, attr_val):
		lustre_util = lustre_ldap()
		filter = lustre_util.get_filter(self.get_rdn(attr_val))
		result = conn_id.search_s(base, ldap.SCOPE_SUBTREE, filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)

	def get_dn(self,uuid):
		retval = self.devUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self, conn_id, devUUID, netUUID, fnetUUID, id, fid, device, auto, fsType, size):
		modlist = []
		dn = self.get_dn(devUUID)
		modlist.append(("objectClass", [self.objectClass]))
		modlist.append((self.devUUID_attr, devUUID))
		modlist.append((self.netUUID_attr, netUUID))
		modlist.append((self.fnetUUID_attr, fnetUUID))
		modlist.append((self.id_attr, id))
		modlist.append((self.fid_attr, fid))
		modlist.append((self.device_attr, device))
		modlist.append((self.auto_attr, auto))
		modlist.append((self.fsType_attr, fsType))
		modlist.append((self.size_attr, size))
		modlist.append(("fs", ["lustre"]))
		status = 0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			#sys.exit(1)
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
		self.objectClass = "lustreOBD"
		self.obdUUID = 0
		self.devName = ""
		self.devUUID = 0
		self.fUUID = 0

		self.lustreDev = 0

		self.obdUUID_attr = "obdUUID"
		self.devName_attr = "devName"
		self.devUUID_attr = "devUUID"
		self.fUUID_attr = "fUUID"
		self.type = "OBD"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self,attr_value):
		retval = "(objectClass="+self.objectClass+") (obdUUID="+attr_value+")"
		return retval

	def init_node(self, record):
		self.obdUUID = record[0][1][self.obdUUID_attr][0]
		self.devName = record[0][1][self.devName_attr][0]
		self.devUUID = record[0][1][self.devUUID_attr][0]
		self.fUUID = record[0][1][self.fUUID_attr][0]

	def getEntry_from_ldap(self, conn_id, base, attr_val):
		lustre_util = lustre_ldap()
		filter = lustre_util.get_filter(self.get_rdn(attr_val))
		result = conn_id.search_s(base, ldap.SCOPE_SUBTREE, filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)

		if self.devUUID:
			self.lustreDev = LustreDevice()
			self.lustreDev.getEntry_from_ldap(conn_id, base, self.devUUID)


	def get_dn(self,uuid):
		retval = self.obdUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self, conn_id, obdUUID, devName, devUUID, fUUID):
		modlist = []
		dn=self.get_dn(obdUUID)
		modlist.append(("objectClass", [self.objectClass]))
		modlist.append((self.obdUUID_attr, obdUUID))
		modlist.append((self.devName_attr, devName))
		modlist.append((self.devUUID_attr, devUUID))
		modlist.append((self.fUUID_attr, fUUID))
		modlist.append(("fs", ["lustre"]))
		status = 0
		try:
			conn_id.add_s(dn, modlist)
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

	def addEntry_into_ldap(self, conn_id, ldlmUUID, devName):
		modlist=[]
		dn=self.get_dn(ldlmUUID)
		modlist.append(("objectClass", self.objectClass))
		modlist.append((self.ldlmUUID_attr, ldlmUUID))
		modlist.append((self.devName_attr, devName))
		modlist.append(("fs", "lustre"))
		status=0
		try:
			conn_id.add_s(dn,modlist)
		except _ldap.LDAPError:
			print "not added"
			#sys.exit(1)
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
		self.objectClass = "lustreNetwork"
		self.netUUID = 0
		self.id = 0
		self.fnetUUID = 0
		self.netType = ""
		self.netAddress = ""
		self.port = 0
		self.recvMem = 0
		self.sendMem = 0

		self.netUUID_attr = "netUUID"
		self.fnetUUID_attr = "fnetUUID"
		self.id_attr = "id"
		self.netType_attr = "netType"
		self.netAddress_attr = "netAddress"
		self.port_attr = "port"
		self.recvMem_attr = "recvMem"
		self.sendMem_attr = "sendMem"
		self.type = "net"

	def get_object_class(self):
		return self.objectCalss

	def get_rdn(self, attr_value):
		retval = "(objectClass="+self.objectClass+") (netUUID="+attr_value+")"
		return retval

	def init_node(self, record):
		self.netUUID = record[0][1][self.netUUID_attr][0]
		self.fnetUUID = record[0][1][self.fnetUUID_attr][0]
		self.id = record[0][1][self.id_attr][0]
		self.netType = record[0][1][self.netType_attr][0]
		self.netAddress = record[0][1][self.netAddress_attr][0]
		self.port = record[0][1][self.port_attr][0]
		self.recvMem = record[0][1][self.recvMem_attr][0]
		self.sendMem = record[0][1][self.sendMem_attr][0]

	def getEntry_from_ldap(self, conn_id, base, attr_val):
		lustre_util = lustre_ldap()
		filter = lustre_util.get_filter(self.get_rdn(attr_val))
		result = conn_id.search_s(base, ldap.SCOPE_SUBTREE, filter)
		if result == []:
			print "Error No Results found"
			sys.exit(1)
		self.init_node(result)


	def get_dn(self, uuid):
		retval = self.netUUID_attr+"="+uuid+",type="+self.type+",fs=lustre"
		return retval

	def addEntry_into_ldap(self,conn_id, id, netUUID, fnetUUID, netType, netAddress, port, recvMem, sendMem):
		modlist = []
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
			#sys.exit(1)
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
                if mdsUUIDs:
		    modlist.append((self.mdsUUIDs_str,mdsUUIDs))
                if ostUUIDs:
		    modlist.append((self.ostUUIDs_str,ostUUIDs))
                if clientUUID:
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
			






           
net_uuids = []
def loadNetworkconfig(dom_node,node):
      global net_uuids
      node_name = get_attr(node,'name')
      net = Network(dom_node) 
      net_uuids.append(net.uuid)
      failnetUUID = net.uuid
      lustreNet = LustreNet()
      lustreNet.initobj(node_name,net.uuid,failnetUUID,net.net_type,net.nid,net.port,net.send_mem,net.recv_mem)
      lustreNet.addEntry_into_ldap(connId, node_name, net.uuid, failnetUUID, net.net_type, str(net.nid), str(net.port), str(net.send_mem), str(net.recv_mem))


ldlm_uuid = 0
def loadLDLMconfig(dom_node,node):
    "This is fill LDLM details...:"
    global ldlm_uuid
    ldlm  = LDLM(dom_node)
    ldlm_uuid = ldlm.uuid
    lustreLdlm = LustreLdlm()
    lustreLdlm.initobj(ldlm.uuid,ldlm.name) 
    lustreLdlm.addEntry_into_ldap(connId, ldlm.uuid, ldlm.name)

lov_uuids = []
def loadLOVconfig(dom_node,node): 
        global lov_uuids
        lov_uuid = get_first_ref(dom_node, 'lov')
        lov_node = lookup(dom_node.parentNode, lov_uuid)
        lov = LOV(lov_node)
        lov_uuids.append(lov.uuid)
        node_name = get_attr(node,'name')
        osc_uuids = []
        for uuid in lov.devlist:
              osc_uuids.append(str(uuid))
        objlov = LustreLov()
        objlov.initobj( lov.uuid, lov.name, osc_uuids, lov.stripe_off, lov.stripe_sz, lov.stripe_cnt, lov.pattern)
        objlov.addEntry_into_ldap(connId, lov.uuid, lov.name, osc_uuids, str(lov.stripe_off), str(lov.stripe_sz), str(lov.stripe_cnt), str(lov.pattern))

	lov_devs = lov_node.getElementsByTagName('devices')
	devlist = get_all_refs(lov_devs[0], 'osc')
        for osc_uuid in devlist:
            osc_node = lookup(dom_node.parentNode,osc_uuid)
            osc = OSC(osc_node) 
            lustreOsc = LustreOsc()
            lustreOsc .initobj( osc.uuid, osc.name, str(osc.obd_uuid), str(osc.ost_uuid))
            lustreOsc .addEntry_into_ldap(connId, osc.uuid, osc.name, str(osc.obd_uuid), str(osc.ost_uuid))

mds_uuids = []
def loadMDSconfig( dom_node,node):
    global mds_uuids 
    node_name = getName(node) 
    mds = MDS(dom_node)
    mds_net = mds.get_server()

    netuuid = mds_net.uuid
    failnetuuid = netuuid
    fid = mds_net.nid 
    device_name = new_name('DEVICE_'+node_name) 
    devuuid = new_uuid(device_name)
    lov_uuid = get_first_ref(dom_node, 'lov')

    objdevice = LustreDevice()
    objdevice.initobj( devuuid, netuuid, netuuid, node_name, node_name, mds.devname, str(mds.format), str(mds.fstype), str(mds.size))
    objdevice.addEntry_into_ldap(connId, devuuid, netuuid, netuuid, node_name, node_name, str(mds.devname), str(mds.format), str(mds.fstype), str(mds.size))

    lovcfg_uuid = get_first_ref(node, 'lovconfig')
    lovcfg = 0
    if lovcfg_uuid:
        lovcfg_node = lookup(dom_node.parentNode, lovcfg_uuid )
        lovcfg = LOVConfig(lovcfg_node)
    lov_uuid = 0
    if lovcfg:
	lov_uuid = str(lovcfg.lov_uuid)
	
    lustreMds = LustreMds()
    lustreMds.initobj(mds.uuid,mds.name,devuuid, lov_uuid, mds.uuid)
    lustreMds.addEntry_into_ldap(connId, mds.uuid, mds.name, devuuid, lov_uuid, mds.uuid)
    mds_uuids.append(mds.uuid)
      

def loadOBDconfig(dom_node,node):
     global net_uuids
     node_name = get_attr(node,'name')
     obd = OBD(dom_node)
     device_name = new_name('DEVICE_'+node_name)
     devuuid = new_uuid(device_name)

     lustreDev = LustreDevice()
     lustreDev.initobj(devuuid, net_uuids[0], net_uuids[0], node_name, node_name, str(obd.devname), str(obd.format), str(obd.fstype), str(obd.size))
     lustreDev.addEntry_into_ldap(connId, devuuid, net_uuids[0], net_uuids[0], node_name, node_name, str(obd.devname), str(obd.format), str(obd.fstype), str(obd.size))

     lustreObd = LustreObd()
     lustreObd.initobj(obd.uuid, obd.name, obd.obdtype, devuuid, obd.uuid)
     lustreObd.addEntry_into_ldap(connId, obd.uuid, obd.name, devuuid, obd.uuid)


mount_uuids = []
def loadMountpointconfig(dom_node,node):
    global mount_uuids
    node_name = get_attr(node,'name')
    mount = Mountpoint(dom_node)
              
    mountuuid = new_uuid(mount.name)
    mount_uuids.append(mountuuid)
    lustreMount = LustreMount()
    lustreMount.initobj( mountuuid, str(mount.mds_uuid), str(mount.lov_uuid), str(mount.path), "No")
    lustreMount.addEntry_into_ldap(connId, mountuuid, str(mount.mds_uuid), str(mount.lov_uuid),str(mount.path), "No")
    


ost_uuids = []
def loadOSTconfig(dom_node,node):
    global ost_uuids
    ost = OST(dom_node)
    node_name = get_attr(node,'name')

    lustreOst = LustreOst()
    lustreOst.initobj(ost.uuid, ost.name, ost.obd_uuid)
    lustreOst.addEntry_into_ldap(connId, ost.uuid, ost.name, str(ost.obd_uuid))
    ost_uuids.append(ost.uuid)
 	
############################################################
# lconf level logic
# Start a service.




def LoadProfile(lustreNode,profileNode,node):
    global mount_uuids
    global profile_uuid
    node_name = get_attr(node,'name')
    if not profileNode:
	panic("profile:",profile,"not found.")
    services = getServices(lustreNode,profileNode)
    if services:
       for service in services:
	   dom_node = service
           type = getServiceType(dom_node)
           if type == 'ldlm':
               loadLDLMconfig(dom_node,node)  
           elif type == 'obd':		    
               loadOBDconfig(dom_node,node) 
           elif type == 'lovconfig':
               loadLOVconfig(dom_node,node)
           elif type == 'network':
               loadNetworkconfig(dom_node,node)
           elif type == 'ost':
               loadOSTconfig(dom_node,node)
           elif type == 'mds':
               loadMDSconfig(dom_node,node)
           elif type == 'mountpoint':
	       loadMountpointconfig(dom_node,node)
           else:
               panic ("unknown service type:", type)


    clientuuid = 0
    if mount_uuids:
        clientuuid = node_name + "clientUUID"	
        lustre_Node = LustreNode(node_name)
        lustreClient = LustreClient(lustre_Node)
        lustreClient.initobj(clientuuid, mount_uuids, net_uuids)
        lustreClient.addEntry_into_ldap(connId, clientuuid, mount_uuids, net_uuids)


    profile_uuid = str(node_name+"profileUUID")
    nodeprofile = LustreNodeProfile()
    nodeprofile.initobj(profile_uuid, mds_uuids, ost_uuids, clientuuid)
    nodeprofile.addEntry_into_ldap(connId, profile_uuid, mds_uuids, ost_uuids, clientuuid)
     
def Initilize_globals():
    global mds_uuids
    global ost_uuids
    global net_uuids
    global clientuuid
    global profile_uuid
    global ldlm_uuid
    global mount_uuids 
    mount_uuids = []
    mds_uuids = []
    ost_uuids = []
    net_uuids = []
    clientuuid = 0
    profile_uuid = 0
    ldlm_uuid = 0

def print_globals():
    global mds_uuids
    global ost_uuids
    global net_uuids
    global clientuuid
    global profile_uuid
    global ldlm_uuid
    print "mds_uuids :", mds_uuids 
    print "ost_uuids :", ost_uuids 
    print "net_uuids :", net_uuids 
    print "client uuid :", clientuuid 
    print "profile_uuid :", profile_uuid 
    print "ldlm_uuid :", ldlm_uuid 

def loadXml(lustreNode):
    global net_uuids
    global ldlm_uuid
    global profile_uuid
    dom_node = None
    Initilize_globals()

    global connId
    server = "blackswan.india.hp.com"
    port=389
    binddn="cn=Manager,fs=lustre"
    base="fs=lustre"
    myCon=MyConn(server,port)
    myCon.open()
    connId=myCon.id

    nodelist = []
    nodelist = lustreNode.getElementsByTagName('node')
    for i in range(len(nodelist)):
        node_name = getName(nodelist[i])
        print "node name in loadXml :", node_name
	node_uuid = getUUID(nodelist[i])
        dom_node = getByName(lustreNode, node_name, 'node') 
        if dom_node == None:
	   break
	Node = LustreNode(node_name)
        reflist = dom_node.getElementsByTagName('profile')
        if reflist:
            for profile in reflist:
       	        LoadProfile(lustreNode,profile,dom_node)
	Node.initobj(node_name,node_uuid,net_uuids,profile_uuid,net_uuids,ldlm_uuid)
	Node.addEntry_into_ldap(connId,node_name,node_uuid,net_uuids,profile_uuid,net_uuids,ldlm_uuid)
        Initilize_globals()
	print "initilized for node:", node_name

        
connId = 0
