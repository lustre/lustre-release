import os, yaml, pathlib, re, threading, time
from lutf import me
import lutf_agent
from clutf_global import *
from lutf_basetest import BaseTest
from lutf_cmd import lutf_exec_local_cmd
from lustre_node import SimpleLustreNode
from lustre_roles import *
import lnet
from fio import FioTraffic
from lutf_exception import *
from lutf_file import *
from lutf_utils import *
import lutf_common_def as common
import logging

class SimpleLustreFS():
	def __init__(self, agent_list):
		self.__lustre_nodes = {}
		self.__mgs_nids = []
		self.__client_nodes = []
		self.__mgs_nodes = []
		self.__oss_nodes = []
		for agent in agent_list:
			self.__lustre_nodes[agent] = SimpleLustreNode(target=agent)
		for key, node in self.__lustre_nodes.items():
			if node.get_lustre_role() == LUSTRE_NODE_ROLE_MGS:
				self.__mgs_nodes.append(node)
		for key, node in self.__lustre_nodes.items():
			if node.get_lustre_role() == LUSTRE_NODE_ROLE_OST:
				self.__oss_nodes.append(node)
		for key, node in self.__lustre_nodes.items():
			if node.get_lustre_role() == LUSTRE_NODE_ROLE_CLIENT:
				self.__client_nodes.append(node)
		if len(self.__mgs_nodes) == 0 or \
		   len(self.__oss_nodes) == 0 or \
		   len(self.__client_nodes) == 0:
			raise LUTFError("Bad cluster clients = %d, OSS = %d, MGS = %d" %
				  (len(client), len(oss), len(mgs)))

	def lustre_node_key_by_value(self, value):
		for key, node in self.__lustre_nodes.items():
			if value == node:
				return key
		return None

	def list_nids(self, nodes):
		nids = []
		for n in nodes:
			node_nids = n.list_nids()
			if len(node_nids) == 0:
				logging.debug("node %s wasn't configured" % n.get_node_name())
				continue
			nids += node_nids
		return nids

	def get_mgs_nodes(self):
		return self.__mgs_nodes

	def get_oss_nodes(self):
		return self.__oss_nodes

	def get_client_nodes(self):
		return self.__client_nodes

	def get_mgs_nids(self):
		return self.__mgs_nids

	def mount_osses(self, num_oss=100):
		if num_oss < 1:
			raise LUTFError("bad parameters")

		for i in range(0, len(self.__oss_nodes)):
			if i >= num_oss:
				break
			self.__oss_nodes[i].configure_lustre(mgs_nids=self.__mgs_nids, index=i)

	def configure_nets(self, mgs={}, oss={}, client={}):
		for n in self.__mgs_nodes:
			if len(mgs) == 0:
				net_map = {'tcp': [n.list_intfs()[0]]}
			else:
				net_map = mgs
			n.configure_net(net_map)
			n.commit()
			self.__mgs_nids = self.list_nids(self.__mgs_nodes)
		for n in self.__oss_nodes:
			if len(mgs) == 0:
				net_map = {'tcp': [n.list_intfs()[0]]}
			else:
				net_map = oss
			n.configure_net(net_map)
			n.commit()
		for n in self.__client_nodes:
			if len(mgs) == 0:
				net_map = {'tcp': [n.list_intfs()[0]]}
			else:
				net_map = client
			n.configure_net(net_map)
			n.commit()

	def mount_mgses(self, num_mgs=100):
		if num_mgs < 1:
			raise LUTFError("bad parameters")

		for i in range(0, len(self.__mgs_nodes)):
			if i >= num_mgs:
				break
			#self.__mgs_nodes[i].configure_lustre(mgs_nids=self.__mgs_nids, index=i)
			self.__mgs_nodes[i].configure_lustre(index=i)

	def mount_servers(self, num_mgs=100, num_oss=100):
		if num_mgs < 1 or num_oss < 1:
			raise LUTFError("bad parameters")
		self.mount_mgses(num_mgs)
		self.mount_osses(num_oss)

	def mount_clients(self, num=100):
		for i in range(0, len(self.__client_nodes)):
			if i >= num:
				break
			self.__client_nodes[i].configure_lustre(mgs_nids=self.__mgs_nids)

	def unmount_clients(self):
		for c in self.__client_nodes:
			c.unconfigure_lustre()

	def umount_mgses(self):
		for m in self.__mgs_nodes:
			m.unconfigure_lustre()

	def umount_osses(self):
		for o in self.__oss_nodes:
			o.unconfigure_lustre()

	def umount_servers(self):
		self.umount_osses()
		self.umount_mgses()

	def read_verify_work(self, index, data, path):
		cnode = self.lustre_node_key_by_value(self.__client_nodes[index])
		d = LutfDir(os.path.split(path)[0], target=cnode)
		files = d.listdir()
		if not os.path.split(path)[1] in files:
			raise LUTFError("file is not in directory")
		f = LutfFile(path, full_path=True, target=cnode)
		f.open('rb')
		verify = f.read()
		if data != verify:
			raise LUTFError("Failed to write contents of file")
		f.remove()
		return True

	def write_work(self, index, data):
		mount = self.__client_nodes[index].get_mount_point()
		path = os.path.join(mount, "lustrefs"+str(random.getrandbits(32)) + '.data')
		cnode = self.lustre_node_key_by_value(self.__client_nodes[index])
		f = LutfFile(path, full_path=True, target=cnode)
		f.open('wb')
		f.write(data)
		f.close()
		return path

	def write(self, index, data, thread=False, timeout=30):
		if not thread:
			return self.write_verify_work(index, data)
		cmd_thrd = LutfThread('lustrefs_write', self.write_work,
				      self, index, data)
		cmd_thrd.start()
		time.sleep(timeout)
		if cmd_thrd.isAlive():
			cmd_thrd.raise_exception()
		if not cmd_thrd.rc:
			raise StopIteration("File System Write Expired")
		return cmd_thrd.rc

	def read_verify(self, index, data, path, thread=False, timeout=30):
		if not thread:
			return self.read_verify_work(index, data, path)
		cmd_thrd = LutfThread('lustrefs_read_verify', self.read_verify_work,
				      self, index, data, path)
		cmd_thrd.start()
		time.sleep(timeout)
		if cmd_thrd.isAlive():
			cmd_thrd.raise_exception()
		if not cmd_thrd.rc:
			raise StopIteration("File System Read Expired")
		return cmd_thrd.rc
