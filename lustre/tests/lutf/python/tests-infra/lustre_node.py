import os, yaml, pathlib, re
from lutf import me
import lutf_agent
from clutf_global import *
from lutf_basetest import BaseTest
from lutf_cmd import lutf_exec_local_cmd
from lustre_roles import *
import lnet
from fio import FioTraffic
from lutf_exception import *
import logging
from utility_paths import get_mkfs, MOUNT, UMOUNT, get_lctl, lustre_rmmod, load_lustre

class SimpleLustreNode(BaseTest):
	def __init__(self, script=os.path.abspath(__file__),
		     target=None, exceptions=True):
		super().__init__(script, target=target)
		if target and me.name != target:
			return
		self.__exceptions = exceptions
		# Role of the node is determined based on the name given
		# this is derived from the tests config file. Look at
		# /usr/lib64/lustre/tests/cfg/lutfcfg.sh
		# for an example
		self.__lnet = lnet.TheLNet()
		self.__fio = None
		self.__client_mountp = None
		self.__ost_mountp = None
		self.__ost_formatted = False
		self.__mds_mountp = None
		self.__mds_formatted = False
		self.__mounted = False

		if self.get_nodenum(['mds(.*?)_HOST', 'mdt(.*?)_HOST', 'mgs(.*?)_HOST']):
			self.__role = LUSTRE_NODE_ROLE_MGS
		elif self.get_nodenum(['ost(.*?)_HOST', 'oss(.*?)_HOST']):
			self.__role = LUSTRE_NODE_ROLE_OST
		elif 'client'.upper() in me.name:
			self.__role = LUSTRE_NODE_ROLE_CLIENT
			self.__fio = FioTraffic()
		elif self.get_nodenum(['rtr(.*?)_HOST']):
			self.__role = LUSTRE_NODE_ROLE_ROUTER
		else:
			self.__role = LUSTRE_NODE_ROLE_UNDEFINED
			if self.__exceptions:
				raise LUTFError("Unknown Lustre node type")

	def get_node_name(self):
		return me.my_name()

	def get_node_hostname(self):
		return me.my_hostname()

	def get_mount_point(self):
		if self.__role == LUSTRE_NODE_ROLE_MGS:
			return self.__mds_mountp
		elif self.__role == LUSTRE_NODE_ROLE_OST:
			return self.__ost_mountp
		elif self.__role == LUSTRE_NODE_ROLE_CLIENT:
			return self.__client_mountp
		return None

	def get_peer_stats(self):
		return self.__lnet.get_peer_stats()

	def list_nids(self, match=None):
		if match:
			return self.__lnet.nets.list_nids(match)[0][match]
		else:
			# return all the list of nids
			nids = []
			nets = self.__lnet.nets.list_nids()
			print(nets)
			for net in nets:
				for k, v in net.items():
					nids += v
			return nids

	def list_intfs(self):
		return list(me.list_intfs()['interfaces'].keys())

	def get_lustre_role(self):
		return self.__role

	def check_down(self):
		self.__lnet.update()
		if len(self.__lnet.nets) > 0:
			raise LUTFError("Expect a clean setup")

	def configure_net(self, net_map):
		'''
		Configure based based on mapping provided
		net_map = {'net_name': [devices]}
		'''
		intfs = []
		for k, v in net_map.items():
			for dev in v:
				intfs.append(self.__lnet.make_net(dev))
			self.__lnet.nets[k] = intfs
			if len(intfs) <= 0:
				raise LUTFError("bad configuration. No interfaces provided")

	def configure_route(self, rt_map):
		'''
		Configure based based on mapping provided
		rt_map = {'rnet': [{'gateway': gw, 'hop': hop, 'priority': prio]}
		'''
		for k, v in rt_map.items():
			self.__lnet.routes[k] = v

	def configure_peer(self, peer_map):
		'''
		Configure based based on mapping provided
		peer_map = {'Multi-Rail': mr, 'peer_ni': [nids]}
		'''
		for k, v in peer_map.items():
			peer = self.__lnet.make_peer(v['Multi-Rail'], v['peer_ni'])
			self.__lnet.peers[k] = peer

	def commit(self):
		self.__lnet.configure()
		L1 = lnet.TheLNet()
		L1.update()
		if not self.__lnet.nets == L1.nets:
			raise LUTFError("Failed to configure LNet")

	def configure_lustre(self, mgs_nids=None, index=0, force_format=False):
		'''
		Configure the mount based on the environment variables set
		'''
		if self.__role == LUSTRE_NODE_ROLE_MGS:
			self.__configure_mds(force_format, mgs_nids=mgs_nids, index=index)
		elif self.__role == LUSTRE_NODE_ROLE_OST:
			self.__configure_ost(force_format, mgs_nids=mgs_nids, index=index)
		elif self.__role == LUSTRE_NODE_ROLE_CLIENT:
			self.__configure_client(mgs_nids)
		self.__mounted = True

	def unconfigure_lustre(self):
		'''
		Unconfigure Lustre module
		'''
		if self.__role == LUSTRE_NODE_ROLE_MGS:
			self.__unconfigure_mount(self.__mds_mountp)
		elif self.__role == LUSTRE_NODE_ROLE_OST:
			self.__unconfigure_mount(self.__ost_mountp)
		elif self.__role == LUSTRE_NODE_ROLE_CLIENT:
			self.__unconfigure_mount(self.__client_mountp)
		self.__mounted = False

	def ismounted(self):
		return self.__mounted

	def start_traffic(self, runtime=30, rw='write', blocksize='1M', numjobs=1):
		if not self.__fio:
			err = "Traffic can only be generated from clients"
			if self.__exception:
				raise LUTFError(err)
			return False, err

		self.__fio.load(self.__client_mountp, runtime=runtime, rw=rw, blocksize=blocksize, numjobs=numjobs)
		self.__fio.start()

	def stop_traffic(self):
		self.__fio.stop()

	def get_nodenum(self, patterns):
		m = None
		num = 1
		for e in patterns:
			m = re.search(e.upper(), me.name.upper())
			if m:
				if len(m[1]) > 0:
					num = int(m[1])
				else:
					num = 1
				break
		if not m:
			return 0
		return num

	def __configure_mds(self, force_format, mgs_nids=None, index=0):
		# create mount point
		load_lustre()
		local_path = get_lutf_tmp_dir()
		pathlib.Path(local_path).mkdir(parents=True, exist_ok=True)
		self.__mds_mountp = os.path.join(local_path, 'mnt', 'mds')
		pathlib.Path(self.__mds_mountp).mkdir(parents=True, exist_ok=True)
		mds_num = self.get_nodenum(['mds(.*?)_HOST', 'mdt(.*?)_HOST', 'mgs(.*?)_HOST'])
		if mds_num <= 0:
			raise LUTFError("Couldn't find an mds")
		dev = os.environ['MDSDEV'+str(mds_num)]
		if force_format or not self.__mds_formatted:
			if not mgs_nids:
				lutf_exec_local_cmd(get_mkfs() + ' --fsname=lustrewt --index='+str(index)+' --reformat --mgs --mdt '+ dev)
			elif type(mgs_nids) == list:
				servicenode = ':'.join(mgs_nids)
				lutf_exec_local_cmd(get_mkfs() + ' --fsname=lustrewt --index='+str(index)+' --reformat --mgs --mdt --servicenode='+servicenode+' ' + dev)
			else:
				LUTFError("Unexpected parameter type: 'mgs_nids'")
			self.__mds_formatted = True
		lutf_exec_local_cmd(MOUNT + ' -t lustre ' + dev + ' ' + self.__mds_mountp)

	def __configure_ost(self, force_format, mgs_nids, index=0):
		if not mgs_nids:
			raise LUTFError("mgs nids must be provided")
		if type(mgs_nids) == list:
			nids = ':'.join(mgs_nids)
		elif type(mgs_nids) == str:
			nids = mgs_nids
		else:
			raise LUTFError("mgs_nids of unknown type")

		load_lustre()
		# create mount point
		local_path = get_lutf_tmp_dir()
		pathlib.Path(local_path).mkdir(parents=True, exist_ok=True)
		self.__ost_mountp = os.path.join(local_path, 'mnt', 'ost')
		pathlib.Path(self.__ost_mountp).mkdir(parents=True, exist_ok=True)
		ost_num = self.get_nodenum(['oss(.*?)_HOST', 'ost(.*?)_HOST'])
		if ost_num <= 0:
			raise LUTFError("Couldn't find an ost")
		dev = os.environ['OSTDEV'+str(ost_num)]
		if force_format or not self.__ost_formatted:
			lutf_exec_local_cmd(get_mkfs() + ' --ost --fsname=lustrewt --index=0 --reformat --mgsnode='+nids+' '+ dev)
			self.__ost_formatted = True
		lutf_exec_local_cmd(MOUNT + ' -t lustre ' + dev + ' ' + self.__ost_mountp)

	def __configure_client(self, mgs_nids):
		if not mgs_nids:
			raise LUTFError("mgs nids must be provided")
		if type(mgs_nids) == list:
			nids = ':'.join(mgs_nids)
		elif type(mgs_nids) == str:
			nids = mgs_nids
		else:
			raise LUTFError("mgs_nids of unknown type")

		load_lustre()
		# create mount point
		local_path = get_lutf_tmp_dir()
		pathlib.Path(local_path).mkdir(parents=True, exist_ok=True)
		self.__client_mountp = os.path.join(local_path, 'mnt', 'lustre')
		pathlib.Path(self.__client_mountp).mkdir(parents=True, exist_ok=True)
		lutf_exec_local_cmd(MOUNT + ' -t lustre ' + nids + ':/lustrewt ' + self.__client_mountp)

	def __unconfigure_mount(self, mount_point):
		if not mount_point:
			logging.debug("No mount point provided")
			return
		# create mount point
		try:
			logging.debug('umount ' + mount_point)
			lutf_exec_local_cmd(UMOUNT + ' ' + mount_point)
		except:
			logging.debug('Failed to umount ' + mount_point)
			pass
		try:
			lustre_rmmod()
		except:
			logging.debug('Failed to lustre_rmmod')
			pass

	def set_dynamic_nids(self, value):
		lutf_exec_local_cmd(get_lctl() + ' set_param mgc.*.dynamic_nids='+str(value))

	def get_dynamic_nids(self):
		rc = lutf_exec_local_cmd(get_lctl() + ' get_param mgc.*.dynamic_nids')
		return int(rc[0].decode('utf-8').split('=')[1].strip())
