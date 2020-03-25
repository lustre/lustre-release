from clutf_agent import *
from lutf_common_def import *
from lutf_exception import LUTFError
import yaml, logging, sys, ctypes

class Agent:
	def __init__(self, name, hostname, id, ip, telnet_port, node_type):
		self.name = name
		pref = load_pref()
		self.timeout = pref['RPC timeout']
		#logging.debug('RPC timeout set to: %d' % (self.timeout))
		if node_type == EN_LUTF_MASTER:
			nt = 'MASTER'
		elif node_type == EN_LUTF_AGENT:
			nt = 'AGENT'
		else:
			raise LUTFError("Undefined node type %d for agent %s" % (node_type, name))
		self.info = {name : {'hostname': hostname, 'ip': ip, 'id': id,
				     'telnet-port': telnet_port,
				     'node-type': nt}}

	def get(self):
		return self.info

	def get_ip(self):
		return self.info[self.name]['ip']

	def get_hostname(self):
		return self.info[self.name]['hostname']

	def get_telnet_port(self):
		return self.info[self.name]['telnet-port']

	def set_rpc_timeout(self, timeout):
		self.timeout = timeout

	def send_rpc(self, rpc_type, src, script, cname,
		     mname, fname, *args, **kwargs):

		if not mname and not fname:
			raise LUTFError("A method or a function name need to be specified")

		rpc = populate_rpc_req(src, self.name, rpc_type, script, cname,
				       mname, fname, *args, **kwargs)
		y = yaml.dump(rpc)
		#by = y.encode('utf-8')
		rc, yaml_txt = lutf_send_rpc(self.name, y, self.timeout)
		y = yaml.load(yaml_txt, Loader=yaml.FullLoader)
		# sanity check
		target = y['rpc']['dst']
		if target != src:
			raise LUTFError("RPC intended to %s but I am %s" % (target, src))

		source = y['rpc']['src']
		if source != self.name:
			raise LUTFError("RPC originated from %s but expected from %s" %
					 (source, self.name))

		if y['rpc']['type'] == 'failure':
			raise LUTFError('RPC failure')
		elif y['rpc']['type'] == 'exception':
			if type(y['rpc']['exception']) == str:
				raise LUTFError(nname=source, msg=y['rpc']['exception'])
			else:
				raise y['rpc']['exception']

		return y['rpc']['rc']

	def dump(self):
		print(yaml.dump(self.info, sort_keys=False))

class LutfAgents:
	"""
	A class to access all agents. This is useful to get a view of all agents currently connected
	"""
	def __init__(self):
		self.agent_dict = {}
		self.max = 0
		self.n = 0
		self.reload()

	def __iter__(self):
		self.n = 0
		return self

	# needed for python 3.x
	def __next__(self):
		if self.n < self.max:
			key = list(self.agent_dict.keys())[self.n]
			agent = self.agent_dict[key]
			self.n += 1
			return key, agent
		else:
			raise StopIteration

	def __getitem__(self, key):
		try:
			rc = self.agent_dict[key]
		except:
			raise LUTFError('no entry for', key)
		return rc

	def keys(self):
		self.reload()
		return list(self.agent_dict.keys())

	def values(self):
		self.reload()
		return list(self.agent_dict.values())

	def reload(self):
		self.agent_dict = {}
		self.max = 0
		for x in range(0, MAX_NUM_AGENTS):
			agent = find_agent_blk_by_id(x)
			if agent:
				self.agent_dict[agent.name] = Agent(agent.name,
						agent.hostname, x,
						agent_ip2str(agent),
						agent.telnet_port,
						agent.node_type)
				release_agent_blk(agent, False)
				self.max += 1

	# always update the dictionary for the following two operations
	def dump(self):
		self.reload()
		for k, v in self.agent_dict.items():
			v.dump()

	def enable_hb_check(self):
		agent_enable_hb()

	def disable_hb_check(self):
		agent_disable_hb()


