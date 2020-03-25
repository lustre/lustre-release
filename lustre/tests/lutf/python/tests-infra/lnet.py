from pathlib import Path
import os, shlex, yaml, subprocess, random, time, logging
from lutf_exception import LUTFError, LutfDumper
from lutf_cmd import lutf_exec_local_cmd
from clutf_global import *
from lutf_basetest import BaseTest, lutfrc
from utility_paths import get_lnetctl, lustre_rmmod, LSMOD, MOUNT, load_lnet
import lutf
import lnetconfig

# Collection()
# Parent class which provides method to keep track of the different elements
# in a dictionary. Provides method to iterate and set items, much like a
# dictionary:
#    ex: dict['key'] = value
class Collection:
	def __init__(self, typeof):
		self.__typeof = typeof
		self.__test_db = {}
		self.__max = 0
		self.__n = 0

	def __getitem__(self, key):
		try:
			rc = self.__test_db[key]
		except:
			raise ValueError('no entry for', key)
		return rc

	def __setitem__(self, key, value):
		self.__test_db[key] = self.__typeof(key, value)
		self.__max = len(self.__test_db)

	def __iter__(self):
		self.__n = 0
		return self

	def __next__(self):
		if self.__n < self.__max:
			key = list(self.__test_db.keys())[self.__n]
			suite = self.__test_db[key]
			self.__n += 1
			return key, suite
		raise StopIteration

	def __len__(self):
		return len(list(self.__test_db.keys()))

	def __contains__(self, key):
		return True if key in self.__test_db.keys() else False

	#TODO requires further testing
	def __eq__(self, c1):
		for k, v in self.__test_db.items():
			if k not in c1:
				return False
			if v == c1[k]:
				continue
			else:
				return False
		return True

	def __ne__(self, c1):
		for k, v in self.__test_db.items():
			if k in c1:
				return False
		return True

	def update(self, key, value):
		self.__test_db[key] = self.__typeof(key, value, user=False)
		self.__max = len(self.__test_db)

	def dump(self):
		config = ''
		for k, v in self.__test_db.items():
			config += v.dump()
		return config

	def list_nids(self, match=None):
		nids = []
		list_nidsd = {}
		for k, v in self.__test_db.items():
			key = None
			try:
				key = getattr(v, 'list_nids_key')()
			except:
				pass
			nid = v.list_nids(match)
			if not nid:
				continue
			if key:
				if key not in list_nidsd:
					list_nidsd[key] = []
				if type(nid) is list:
					list_nidsd[key] = list_nidsd[key] + nid
					list_nidsd[key] = [y for x in list_nidsd[key] for y in x]
				else:
					list_nidsd[key].append(nid)
			elif type(nid) is list:
				for n in nid:
					nids.append(n)
			elif type(nid) is str:
				nids.append(nid)
		if len(list_nidsd) > 0:
			nids.append(list_nidsd)
		return nids

	def get(self):
		config = []
		for k, v in self.__test_db.items():
			info = v.get()
			if type(info) is list:
				config = config + info
			else:
				config.append(v.get())
		return config

	def keys(self):
		return list(self.__test_db.keys())

	def values(self):
		return list(self.__test_db.values())

# L.nets['tcp'] = [{'interfaces': 'eth0', 'peer_credits': 128},
#                  {'interfaces': 'eth1', 'peer_credits': 128}]
class LNetNI:
	def __init__(self, name, ni_def, user=True):
		self.__info = {}
		self.name = name
		self.__nid = ''
		self.__net = ''
		if user:
			self.populate(ni_def)
		else:
			self.populate_predef(ni_def)

	def __eq__(self, ni):
		remote = ni.get()
		for k, v in self.__info.items():
			if k in remote:
				# check if they match
				if not v == remote[k]:
					return False
		return True

	def populate(self, ni_def):
		if 'tunables' in self.__info:
			tunables = self.__info['tunables']
		else:
			tunables = {}
		if 'net' in ni_def:
			self.__net = ni_def['net']
			del(ni_def['net'])
		for k, v in ni_def.items():
			if k == 'CPT':
				self.__info[k] == v.replace(',', ' ').split()
			elif k == 'interfaces':
				intf = v.replace(',', ' ').split()
				intfd = {}
				j = 0
				for i in intf:
					if j == 0:
						self.__nid = lutf.me.get_local_interface_ip(i)+'@'+self.__net
					intfd[j] = i
				self.__info[k] = intfd
			elif k == 'credits' or k == 'peer_buffer_credits' or k == 'peer_credits' or k == 'peer_timeout':
				tunables[k] = v
				self.__info['tunables'] = tunables
			else:
				raise ValueError(k, 'unexpected keyword')

	def dump(self):
		return yaml.dump(self.__info, Dumper=LutfDumper, indent=2, sort_keys=False)

	def list_nids(self, match=None):
		if match and match != self.__net:
			return None
		if len(self.__nid) == 0:
			return None
		return self.__nid

	def list_nids_key(self):
		return self.__net

	def get(self):
		return self.__info

	def populate_predef(self, info):
		if 'net' in info:
			self.__net = info['net']
			self.__nid = lutf.me.get_local_interface_ip(info['interfaces'][0])+'@'+self.__net
			del(info['net'])
		self.__info = info

class LNetNetNICol(Collection):
	def __init__(self):
		super().__init__(LNetNI)

class LNetNet:
	def __init__(self, name, args, user=True):
		self.name = name
		self.nis = LNetNetNICol()
		if user:
			for e in args:
				if 'net' not in e:
					e['net'] = self.name
				self.nis[e['interfaces']] = e
		else:
			for e in args:
				if 'net' not in e:
					e['net'] = self.name
				if 'interfaces' in e:
					self.nis.update(e['interfaces'][0], e)

	def __eq__(self, net):
		return self.nis == net.nis

	def list_nids(self, match=None):
		if match and match != self.name:
			return None
		return self.nis.list_nids()

	def get(self):
		config = {'net type':self.name,  'local NI(s)':self.nis.get()}
		return config

	def dump(self):
		config = {'net type':self.name,  'local NI(s)':self.nis.get()}
		return yaml.dump(config, Dumper=LutfDumper, indent=2, sort_keys=False)

class LNetNetCol(Collection):
	def __init__(self):
		super().__init__(LNetNet)

# L.peers['192.168.29.3@tcp'] = {'Multi-Rail': True, 'peer ni':
#		[{'nid': '192.168.29.3@tcp'},
# 		 {'nid': '192.168.29.4@tcp1'}]}
class LNetPeerNI:
	def __init__(self, nid, ni_def, user=True):
		self.__info = {}
		self.__nid = nid
		self.__prim_nid = 'undef'
		if 'primary-nid' in ni_def:
			self.__prim_nid = ni_def['primary-nid']
			del(ni_def['primary-nid'])
		self.populate(ni_def)

	def populate(self, ni_def):
		self.__info['nid'] = ni_def['nid']

	def __eq__(self, ni):
		remote = ni.get()
		for k, v in self.__info.items():
			if k in remote:
				if not v == remote[k]:
					return False
		return True

	def dump(self):
		return yaml.dump(self.__info, Dumper=LutfDumper, indent=2, sort_keys=False)

	def list_nids(self, match=None):
		if match and match != self.__prim_nid:
			return None
		return self.__nid

	def list_nids_key(self):
		return self.__prim_nid

	def get(self):
		return self.__info

	def populate_predef(self, info):
		if 'primary-nid' in info:
			self.__prim_nid = info['primary-nid']
			del(info['primary-nid'])
		self.__info = info

class LNetPeerNICol(Collection):
	def __init__(self):
		super().__init__(LNetPeerNI)

class LNetPeer:
	def __init__(self, primary_nid, args, user=True):
		self.primary_nid = primary_nid
		self.multi_rail = args['Multi-Rail']
		self.peer_nis = LNetPeerNICol()
		for e in args['peer ni']:
			e['primary-nid'] = self.primary_nid
			self.peer_nis[e['nid']] = e

	def __eq__(self, peer):
		return self.get() == peer.get()

	def list_nids(self, match=None):
		if match and match != self.primary_nid:
			return None
		return self.peer_nis.list_nids()

	def dump(self):
		c = self.get()
		return yaml.dump(c, Dumper=LutfDumper, indent=2, sort_keys=False)

	def get(self):
		config = {'primary nid':self.primary_nid,
			  'Multi-Rail': self.multi_rail,
			  'peer ni':self.peer_nis.get()}
		return config

class LNetPeerCol(Collection):
	def __init__(self):
		super().__init__(LNetPeer)

# L.routes['tcp4'] = [{'gateway': '192.168.2.4@tcp', 'hop': -1, 'priority': 0},
# 		      {'gateway': '192.168.4.4@tcp', 'hop': 3, 'priority': 5}]
class LNetGateway:
	def __init__(self, nid, gw):
		self.__info = {}
		self.__nid = nid
		self.__rnet = 'undef'
		if 'rnet' in gw:
			self.__rnet = gw['rnet']
			del(gw['rnet'])
		self.populate(gw)

	def populate(self, gw):
		self.__info['gateway'] = gw['gateway']
		if 'hop' in gw:
			self.__info['hop'] = gw['hop']
		if 'priority' in gw:
			self.__info['priority'] = gw['priority']
		if 'health_sensitivity' in gw:
			self.__info['health_sensitivity'] = gw['health_sensitivity']

	def __eq__(self, gw):
		remote = gw.get()
		for k, v in self.__info.items():
			if k in remote:
				if not v == remote[k]:
					return False
		return True

	def list_nids(self, match=None):
		if match and match != self.__rnet:
			return None
		return self.__nid

	def dump(self):
		return yaml.dump(self.__info, Dumper=LutfDumper, indent=2, sort_keys=False)

	def get(self):
		return self.__info

	def populate_yaml(self, y):
		self.__info = yaml.load(y, Loader=(yaml.FullLoader))

class LNetGatewayCol(Collection):
	def __init__(self):
		super().__init__(LNetGateway)

class LNetRNet:
	def __init__(self, net, args, user=True):
		self.net = net
		self.gateways = LNetGatewayCol()
		if user:
			for e in args:
				e['rnet'] = self.net
				self.gateways[e['gateway']] = e
		else:
			args['rnet'] = self.net
			self.gateways[args['gateway']] = args

	def __eq__(self, rnet):
		me = self.get()
		other = rnet.get()
		if len(me) != len(other):
			return False
		for entry in me:
			if entry not in other:
				return False
		return True

	def append(self, args):
		args['rnet'] = self.net
		self.gateways[args['gateway']] = args

	def list_nids(self, match=None):
		if match and match != self.net:
			return None
		nids = []
		for gw in self.gateways.get():
			nids.append(gw.list_nids())
		return nids

	def list_nids_key(self):
		return self.net

	def dump(self):
		return yaml.dump(self.get(), Dumper=LutfDumper, indent=2, sort_keys=False)
		dumps = []
		for gw in self.gateways.get():
			dumps.append(gw.dump())
		return ''.join(dumps)
		#return self.gateways.dump()

	def get(self):
		config = []
		for gw in self.gateways.get():
			rnet = {'net': self.net}
			rnet.update(gw)
			config.append(rnet)
		return config

class LNetRNetCol(Collection):
	def __init__(self):
		super().__init__(LNetRNet)

class TheLNet(BaseTest):
	'''
	Usage:
	======
	import sys
	import lnet
	L = lnet.TheLNet()
	L.nets['tcp'] = [{'interfaces': 'eth0', 'peer_credits': 128},
			 {'interfaces': 'eth1', 'peer_credits': 128}]
	L.routes['tcp3'] = [{'gateway': '192.168.2.4@tcp', 'hop': -1, 'priority': 0},
			    {'gateway': '192.168.4.4@tcp', 'hop': 3, 'priority': 5}]
	L.routes['tcp4'] = [{'gateway': '192.168.2.4@tcp', 'hop': -1, 'priority': 0},
			    {'gateway': '192.168.4.4@tcp', 'hop': 3, 'priority': 5}]
	L.peers['192.168.29.3@tcp'] = {'Multi-Rail': True, 'peer ni':
			[{'nid': '192.168.29.3@tcp'},
			 {'nid': '192.168.29.4@tcp1'}]}
	L.routes['tcp3'] = [{'gateway': '192.168.2.4@tcp', 'hop': -1, 'priority': 0}]
	L.routing = {'enable': 1}
	L.buffers = {'tiny': 2048, 'small': 16384, 'large': 1024}
	L.global_vars = {'numa_range': 0, 'max_intf': 200, 'discovery': 1, 'drop_asym_route': 0}
	L.configure()

	# Build up the already configured lnet.

	L = lnet.TheLNet()
	L.update()

	# one potential use is:
	# 1. Configure the LNet as in the first example
	# 2. Then read back the configuration into a different TheLNet instance
	# 3. compare

	L.configure()
	L1.update()
	if L != L1:
		print("Failed to configure")
	L1.unconfigure()
	'''
	def __init__(self, script=os.path.abspath(__file__),
		     target=None, exceptions=True):
		super().__init__(script, target=target)
		# only initialize the data if we're going to execute locally
		if target and lutf.me.name != target:
			return
		self.nets = LNetNetCol()
		self.peers = LNetPeerCol()
		self.routes = LNetRNetCol()
		self.routing = {}
		self.buffers = {}
		self.global_vars = {}
		if not self.check_lnet_loaded():
			load_lnet()

	def __eq__(self, L1):
		if self.nets == L1.nets and \
		   self.peers == L1.peers and \
		   self.routes == L1.routes and \
		   self.routing == L1.routing and \
		   self.buffers == L1.buffers and \
		   self.global_vars == L1.global_vars:
			return True
		return False

	def __ne__(self, L1):
		if self.nets != L1.nets and \
		   self.peers != L1.peers and \
		   self.routes != L1.routes and \
		   self.routing != L1.routing and \
		   self.buffers != L1.buffers and \
		   self.global_vars != L1.global_vars:
			return True
		return False

	def check_lnet_loaded(self):
		rc = lutf_exec_local_cmd(LSMOD)
		if not rc:
			return False
		if 'lnet' in rc[0].decode('utf-8'):
			return True
		else:
			return False

	def export(self, op=print):
		self.export_nets(op)
		self.export_peers(op)
		self.export_routes(op)
		self.export_routing(op)
		self.export_global(op)

	def export_nets(self, op=print, net=None):
		if net:
			try:
				net_config = {'net': self.nets[net].get()}
			except:
				return
		else:
			net_config = {'net': self.nets.get()}
		if len(net_config['net']) and op:
			op(yaml.dump(net_config, Dumper=LutfDumper, indent=2,
				sort_keys=False))
		return net_config

	def export_peers(self, op=print):
		peer_config = {'peer': self.peers.get()}
		if len(peer_config['peer']) and op:
			op(yaml.dump(peer_config, Dumper=LutfDumper, indent=2,
				sort_keys=False))
		return peer_config

	def export_routes(self, op=print):
		route_config = {'route': self.routes.get()}
		if len(route_config['route']) and op:
			op(yaml.dump(route_config, Dumper=LutfDumper, indent=2,
				sort_keys=False))
		return route_config

	# TODO: Incomplete routing implementation
	def export_routing(self, op=print):
		routing = {}
		buffers = {}
		if len(self.routing):
			routing = {'routing': self.routing}
			if op:
				op(yaml.dump(routing, Dumper=LutfDumper, indent=2,
					sort_keys=False))
		if len(self.buffers):
			buffers = {'buffers': self.buffers}
			if op:
				op(yaml.dump(buffers, Dumper=LutfDumper, indent=2,
					sort_keys=False))
		return {**routing, **buffers}

	def export_global(self, op=print):
		global_vars = {}
		if len(self.global_vars):
			global_vars = {'global': self.global_vars}
			if op:
				op(yaml.dump(global_vars, Dumper=LutfDumper, indent=2,
					sort_keys=False))
		return global_vars

	def yaml_config_helper(self, export_op, lnetctl_cmd, keep=False, **args):
		local_path = get_lutf_tmp_dir()
		Path(local_path).mkdir(parents=True, exist_ok=True)
		fname = os.path.join(local_path, "lnet_gen_"+str(random.getrandbits(32)) + '.yaml')
		with open(fname, 'w') as f:
			export_op(f.write, **args)
		if not self.check_lnet_loaded():
			load_lnet()
		lutf_exec_local_cmd(lnetctl_cmd+" "+fname)
		if keep:
			print("configuration file:", fname)
		else:
			os.remove(fname)

	def configure(self, keep=False):
		'''
		Configure LNet with the information stored in this instance
		'''
		if self.check_lnet_loaded():
			lutf_exec_local_cmd(get_lnetctl() + " export")
		self.yaml_config_helper(self.export, get_lnetctl() + " import", keep=keep)

	def import_yaml(self, op=print, yaml_data=None):
		if op and yaml_data:
			op(yaml.dump(yaml_data, Dumper=LutfDumper, indent=2,
				sort_keys=False))

	def import_config(self, data):
		self.yaml_config_helper(self.import_yaml, get_lnetctl() + " import", keep=False, yaml_data=data)
		self.update()

	def import_del(self, data):
		self.yaml_config_helper(self.import_yaml, get_lnetctl() + " import --del", keep=False, yaml_data=data)
		self.update()

	def configure_yaml(self, yaml):
		# update our internal structure
		self.update(yaml)
		# configure LNet
		self.configure()

	def unconfigure(self):
		'''
		Unconfigure LNet
		'''
		if self.check_lnet_loaded():
			rc = lutf_exec_local_cmd(MOUNT)
			output = rc[0].decode('utf-8')
			if 'type lustre' in output:
				raise LUTFError("Lustre is still mounted")
			if not lustre_rmmod():
				lnetconfig.lustre_lnet_config_lib_uninit()
				raise LUTFError("lustre_rmmod failed")
		self.update()

	def unconfigure_net(self, net):
		'''
		unconfigure the net specified
		'''
		self.yaml_config_helper(self.export_nets, get_lnetctl() + " import --del", net=net)
		self.update()

	def add_ni(self, net, dev):
		'''
		add an NI
		'''
		lutf_exec_local_cmd(get_lnetctl() + " net add --net %s --if %s" % (net, dev))
		self.update()

	def del_net(self, net):
		'''
		delete an entire net
		'''
		lutf_exec_local_cmd(get_lnetctl() + " net del --net " + net)
		self.update()

	def del_ni(self, net, dev):
		'''
		delete an interface
		'''
		lutf_exec_local_cmd(get_lnetctl() + " net del --net %s --if %s" % (net, dev))
		self.update()

	def update(self, yamlcfg=None):
		'''
		This method exports the LNet configuration using
			lnetctl export --backup > config.yaml
		It then parses that file and stores the data.
		'''
		self.nets = LNetNetCol()
		self.peers = LNetPeerCol()
		self.routes = LNetRNetCol()
		self.routing = {}
		self.buffers = {}
		self.global_vars = {}

		# if no lnet then just reset the internal data.
		if not self.check_lnet_loaded():
			return

		if not yamlcfg:
			rc = lutf_exec_local_cmd(get_lnetctl() + " export --backup")
			y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		else:
			y = yamlcfg
		# Test code
		#with open('cfg.yaml', 'r') as f:
		#	y = yaml.load(f, Loader=yaml.FullLoader)
		if 'net' in y:
			for entry in y['net']:
				# don't consider the loopback entry
				if entry['net type'] == 'lo':
					continue
				self.nets.update(entry['net type'], entry['local NI(s)'])
		else:
			self.nets = LNetNetCol()

		if 'peer' in y:
			for e in y['peer']:
				self.peers.update(e['primary nid'], e)
		else:
			self.peers = LNetPeerCol()

		if 'route' in y:
			for e in y['route']:
				if e['net'] in self.routes:
					self.routes[e['net']].append(e)
				else:
					self.routes.update(e['net'], e)
		else:
			self.routes = LNetRNetCol()

		if 'routing' in y:
			self.routing = y['routing']
		else:
			self.routing = {}

		if 'buffers' in y:
			self.buffers = y['buffers']
		else:
			self.buffers = {}

		if 'global' in y:
			self.global_vars = y['global']
		else:
			self.global_vars = {}

	def get_peers(self, nid=None):
		if nid:
			cmd = get_lnetctl() + " peer show --nid " + nid
		else:
			cmd = get_lnetctl() + " peer show"
		rc = lutf_exec_local_cmd(cmd)
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		return y

	def get_peers_detail(self, nid=None):
		if nid:
			cmd = get_lnetctl() + " peer show -v 4 --nid " + nid
		else:
			cmd = get_lnetctl() + " peer show -v 4"
		rc = lutf_exec_local_cmd(cmd)
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		return y

	def get_peer_stats(self, nid=None):
		y = self.get_peers_detail(nid=nid)
		for lp in y['peer']:
			del(lp['Multi-Rail'])
			del(lp['peer state'])
			for lpni in lp['peer ni']:
				del(lpni['state'])
				del(lpni['max_ni_tx_credits'])
				del(lpni['available_tx_credits'])
				del(lpni['min_tx_credits'])
				del(lpni['tx_q_num_of_buf'])
				del(lpni['available_rtr_credits'])
				del(lpni['min_rtr_credits'])
				del(lpni['refcount'])
		return y['peer']

	def get_net(self, net=None):
		if net and type(net) == str:
			cmd = get_lnetctl() + " net show --net " + net
		else:
			cmd = get_lnetctl() + " net show"
		rc = lutf_exec_local_cmd(cmd)
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		return y

	def get_net_detail(self, net=None):
		if net and type(net) == str:
			cmd = get_lnetctl() + " net show -v 4 --net " + net
		else:
			cmd = get_lnetctl() + " net show -v 4"
		rc = lutf_exec_local_cmd(cmd)
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		return y

	def get_net_stats(self, net=None):
		y = self.get_net_detail(net)
		# delete the lo. It's always the first one
		del(y['net'][0])
		for nt in y['net']:
			for ni in nt['local NI(s)']:
				del(ni['status'])
				del(ni['interfaces'])
				del(ni['tunables'])
		return y['net']

	def get_stats(self):
		rc = lutf_exec_local_cmd(get_lnetctl() + " stats show")
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		return y

	def get_global(self):
		rc = lutf_exec_local_cmd(get_lnetctl() + " global show")
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		return y

	def set_global_param(self, name, value):
		rc = lutf_exec_local_cmd(get_lnetctl() + " set %s %d" % (name, value))

	def get_config(self):
		rc = lutf_exec_local_cmd(get_lnetctl() + " export --backup")
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		return y

	def discover(self, nid):
		logging.debug(get_lnetctl() + " discover %s" % nid)
		rc = lutf_exec_local_cmd(get_lnetctl() + " discover %s" % nid)
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		return y

	def ping(self, nid):
		rc = lutf_exec_local_cmd(get_lnetctl() + " ping %s" % nid)
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		return y

	def make_net(self, interface_name=None, peer_credits=128, peer_timeout=180,
		     peer_buffer_credits=0, credits=256):
		if not interface_name:
			raise LUTFError("interface name for net not specified")
		return {'interfaces': interface_name, 'peer_credits': peer_credits,
			 'peer_timeout': peer_timeout, 'peer_buffer_credits': peer_buffer_credits,
			 'credits': credits}

	def make_route(self, gw=None, hop=-1, priority=0, sen=1):
		if not gw:
			raise LUTFError("gateway not specified for route")
		return {'gateway': gw, 'hop': hop, 'priority': priority, 'health_sensitivity': sen}

	def make_peer(self, mr=True, *peer_nis):
		lpnis = []
		for e in peer_nis:
			lpnis.append({'nid': e})
		return {'Multi-Rail': mr, 'peer_ni': lpnis}

