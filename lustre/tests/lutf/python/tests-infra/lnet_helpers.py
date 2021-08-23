import os, re
import yaml, ast, psutil
import lnetconfig, logging
from lutf import agents, me
from lutf_basetest import BaseTest, lutfrc
from lnet import TheLNet
from lutf_exception import LUTFError
from lutf_cmd import lutf_exec_local_cmd
from utility_paths import get_lnetctl, CAT, MAN

LNET_NRB_TINY_MIN = 512
LNET_NRB_TINY = LNET_NRB_TINY_MIN * 4
LNET_NRB_SMALL_MIN = 4096
LNET_NRB_SMALL = LNET_NRB_SMALL_MIN * 4
LNET_NRB_LARGE_MIN = 256
LNET_NRB_LARGE = LNET_NRB_LARGE_MIN * 4

class LNetHelpers(BaseTest):
	def __init__(self, script=os.path.abspath(__file__),
		     target=None, exceptions=True):
		super().__init__(script, target=target)
		self.exceptions = exceptions
		self.__nid = None
		logging.debug('LNetHelpers: %s == %s' % (me.name, target))
		if not target or me.name == target:
			logging.debug('Initializing LNetHelper')
			rc = lnetconfig.lustre_lnet_config_lib_init()
			if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
				raise LUTFError("Failed to initialize the liblnetconfig library")

	def __del__(self):
		lnetconfig.lustre_lnet_config_lib_uninit()
		super().__del__()

	def uninit(self):
		logging.debug('uninit: Uninitializing LNetHelper')
		lnetconfig.lustre_lnet_config_lib_uninit()

	def set_exception(self, exception):
		self.exceptions = exception

	def get_mem_info(self):
		return psutil.virtual_memory()

	def configure_lnet(self):
		L = TheLNet()

	def unconfigure_lnet(self):
		L = TheLNet()
		L.unconfigure()

	def get_num_cpus(self):
		return me.get_num_cpus()

	def configure_net(self, net, pintfs=None, pycfg=None):
		L = TheLNet()
		if pycfg:
			L.configure_yaml(pycfg)
			L1 = TheLNet()
			L1.update()
			if not L1.nets == L.nets and not net in L1.nets:
					if self.exceptions:
						raise LUTFError("LNet %s configuration failed" % net)
					return False, net
			return True, None

		if pintfs:
			intfs = pintfs
		else:
			intfs = self.get_available_devs()
		if len(intfs) == 0:
			if self.exceptions:
				raise LUTFError("node doesn't have any interfaces")
			return False, net
		# configure the first interface
		nets = []
		for intf in intfs:
			logging.debug("configuring: %s" % intf)
			nets.append(L.make_net(intf))
		logging.debug(str(nets))
		L.nets[net] = nets
		L.configure()
		L1 = TheLNet()
		L1.update()
		if not L1.nets == L.nets and not net in L1.nets:
				if self.exceptions:
					raise LUTFError("LNet %s configuration failed" % net)
				return False, net
		net_show = L1.get_net()
		for n in net_show['net']:
			if n['net type'] == 'lo' or n['net type'] != net:
				continue
			self.__nid = n['local NI(s)'][0]['nid']
			break

		logging.debug(self.__nid)
		return True, None

	def unconfigure_net(self, net):
		if not net:
			return True
		L = TheLNet()
		L.update()
		L.unconfigure_net(net)
		nets = L.export_nets(op=None)
		for n in nets['net']:
			if net == n['net type']:
				if self.exceptions:
					raise LUTFError("net %s was not unconfigure properly" % net)
				return False
		return True

	def get_nid(self):
		return self.__nid

	def list_nids(self):
		L = TheLNet()
		nids = []
		net_show = L.get_net()
		for n in net_show['net']:
			if n['net type'] == 'lo':
				continue
			for nid in n['local NI(s)']:
				nids.append(nid['nid'])
		return nids

	def get_available_devs(self):
		intfs = me.list_intfs()
		return list(intfs['interfaces'].keys())

	def get_available_intfs(self):
		return me.list_intfs()

	def api_config_ni(self, net, device_list=[], global_cpts=None, ip2nets=None,
			  peer_credits=128, peer_timeout=180, peer_buffer_credits=0,
			  credits=256, conns_per_peer = -1):
		tunables = lnetconfig.lnet_ioctl_config_lnd_tunables()
		tunables.lt_cmn.lct_peer_timeout = peer_timeout
		tunables.lt_cmn.lct_peer_tx_credits = peer_credits;
		tunables.lt_cmn.lct_max_tx_credits = credits;
		tunables.lt_cmn.lct_peer_rtr_credits = peer_buffer_credits

		if (ip2nets == None):
			nwd = lnetconfig.lnet_dlc_network_descr()
			lnetconfig.lustre_lnet_init_nw_descr(nwd)
			nwd.nw_id = lnetconfig.libcfs_str2net(net)
			devices_str = ''
			for device in device_list[:-1]:
				devices_str += device + ','
			if len(device_list) > 0:
				devices_str += device_list[-1]
			rc = lnetconfig.lustre_lnet_parse_interfaces(devices_str, nwd)
			if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
				if self.exceptions:
					raise LUTFError("Failed to parse interfaces %d" % rc)
				return False, [rc, net, device_list, global_cpts, ip2nets]
		else:
			nwd = None
		g_cpts = None
		if global_cpts != None and type(global_cpts) is list:
			rc, g_cpts = lnetconfig.cfs_expr_list_parse(str(global_cpts), len(str(global_cpts)), 0, lnetconfig.UINT_MAX)
			if rc != 0:
				if self.exceptions:
					raise LUTFError("Failed to parse global_cpts")
				return False, [rc, net, device_list, global_cpts, ip2nets]
		else:
			g_cpts = None
		rc, yaml_err = lnetconfig.lustre_lnet_config_ni(nwd, g_cpts, ip2nets, tunables, conns_per_peer, -1)
		#Freeing the g_cpts causes a segmentation fault
		#if g_cpts:
		#	lnetconfig.cfs_expr_list_free(g_cpts)
		self.cYAML_free(yaml_err)
		if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
			if self.exceptions:
				raise LUTFError("Failed to config ni %s:%s:%s:%s" %
						(str(net), str(device_list),
						 str(global_cpts), str(ip2nets)))
			return False, [rc, net, device_list, global_cpts, ip2nets]
		return True, [rc, net, device_list, global_cpts, ip2nets]

	def api_del_ni(self, net, device_list):
		nwd = lnetconfig.lnet_dlc_network_descr()
		lnetconfig.lustre_lnet_init_nw_descr(nwd)
		nwd.nw_id = lnetconfig.libcfs_str2net(net)
		devices_str = ''
		for device in device_list[:-1]:
			devices_str += device + ','
		if len(device_list) > 0:
			devices_str += device_list[-1]
		rc = lnetconfig.lustre_lnet_parse_interfaces(devices_str, nwd)
		if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
			if self.exceptions:
				raise LUTFError("Failed to parse interfaces")
			return False, [rc, net, device_list]
		rc, yaml_err = lnetconfig.lustre_lnet_del_ni(nwd, -1)
		self.cYAML_free(yaml_err)
		if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
			if self.exceptions:
				raise LUTFError("Failed to del ni")
			return False, [rc, net, device_list]
		return True, [rc, net, device_list]

	def api_check_ni(self, net = None, num = 1, global_cpts=None, iname=None, peer_credits=128,
			 peer_timeout=180, peer_buffer_credits=0, credits=256):
		rc, yaml_show, yaml_err = lnetconfig.lustre_lnet_show_net(net, 0, -1, False)
		err = lnetconfig.cYAML_dump(yaml_err)
		self.cYAML_free(yaml_err)
		if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
			self.cYAML_free(yaml_show)
			if self.exceptions:
				raise LUTFError("Failed to show NIs")
			return False, [rc, num, err]
		else:
			# basic check to make sure there are the right number of nets
			# configured
			show = lnetconfig.cYAML_dump(yaml_show)
			self.cYAML_free(yaml_show)
			pyy = yaml.load(show, Loader=yaml.FullLoader)
			count = len(pyy['net'][0]['local NI(s)'])
			if pyy['net'][0]['net type'] != net or count != num:
				if self.exceptions:
					raise LUTFError("Show doesn't match %d != %d\n%s" % (count, num, show))
				return False, [rc, count, num, show]
			# Check the tunables match
			for n in pyy['net']:
				if n['net type'] == net:
					for i in n['local NI(s)']:
						if iname and iname in list(i['interfaces'].values()):
							if i['tunables']['peer_timeout'] != peer_timeout or \
							   i['tunables']['peer_credits'] != peer_credits or \
							   i['tunables']['peer_buffer_credits'] != peer_buffer_credits or \
							   i['tunables']['credits'] != credits or \
							   (global_cpts and ast.literal_eval(i['CPT']) != global_cpts):
								if self.exceptions:
									raise LUTFError("configured ni tunables don't match")
								return False, [rc, count, num, show]
			return True, [rc, show]

	def api_configure_route(self, rnet=None, gw=None, hop=-1, prio=0, sen=1):
		rc, yaml_err = lnetconfig.lustre_lnet_config_route(rnet, gw, hop, prio, sen, -1)
		self.cYAML_free(yaml_err)
		if rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR:
			if self.exceptions:
				raise LUTFError("failed to configure route. rc=%s, rnet=%s gw=%s hop=%s pio=%s sen=%s" % (str(rc), str(rnet), str(gw), str(hop), str(prio), str(sen)))
			return False, [rnet, gw, hop, prio, sen]

		# check the route was configured as expected
		L1 = TheLNet()
		L1.update()
		L1.export(op=logging.debug)
		if rnet not in L1.routes.keys():
			if self.exceptions:
				raise LUTFError("failed to configure remote net %s" % rnet)
			return False, [rnet, gw, hop, prio, sen]
		route = L1.routes[rnet].get()
		if len(route) == 0:
			if self.exceptions:
				raise LUTFError("failed to configure remote net %s" % rnet)
			return False, [rnet, gw, hop, prio, sen]
		logging.debug(yaml.dump({'original': [rnet, gw, hop, prio, sen], 'configured': route[0]}))
		if route[0]['gateway'] != gw or \
		   route[0]['hop'] != hop or \
		   route[0]['priority'] != prio or \
		   (route[0]['health_sensitivity'] != sen and sen != -1) or \
		   (route[0]['health_sensitivity'] != 1 and sen == -1):
			if self.exceptions:
				raise LUTFError("Configured route is not expected", {'original': [rnet, gw, hop, prio, sen], 'configured': route[0]})
			return False, [[rnet, gw, hop, prio, sen], route[0]]
		return True, [rnet, gw, hop, prio, sen]

	def cYAML_count(self, blk):
		if (blk == None):
			return 0
		yy = yaml.load(blk, Loader=yaml.FullLoader)
		logging.debug(str(yy))
		return len(yy[next(iter(yy))])

	def cYAML_free(self, cyaml):
		if (cyaml):
			lnetconfig.cYAML_free_tree(cyaml.cy_child)

	def api_del_route(self, rnet=None, gw=None):
		# delete route but missing net
		rc, yaml_err = lnetconfig.lustre_lnet_del_route(rnet, gw, -1)
		self.cYAML_free(yaml_err)
		if (rc == lnetconfig.LUSTRE_CFG_RC_MISSING_PARAM):
			if self.exceptions:
				raise LUTFError("Failed to delete route")
			return False, [rc, rnet, gw]
		return True, [rc, rnet, gw]

	def api_check_route(self, num, network = None, gateway = None, hop = -1, prio = -1):
		logging.debug("show route: %s %s %s %s" % (str(network), str(gateway), str(hop), str(prio)))
		rc, yaml_show, yaml_err = lnetconfig.lustre_lnet_show_route(network, gateway, hop, prio, 1, -1, False)
		logging.debug("show_route: rc = %s" % (str(rc)))
		self.cYAML_free(yaml_err)
		if (rc == lnetconfig.LUSTRE_CFG_RC_NO_ERR):
			if yaml_show is None:
				count = 0
			else:
				show = lnetconfig.cYAML_dump(yaml_show)
				count = self.cYAML_count(show)
				logging.debug("%s Routes detected" % (str(count)))
				logging.debug(show)
				# free the memory (This is a call into the C code)
				self.cYAML_free(yaml_show)
			if (count != num):
				if self.exceptions:
					raise LUTFError("%d doesn't match number of configured routes %d" % (count, num))
				return False, [count, num, network, gateway, hop, prio]
		elif num > 0:
			self.cYAML_free(yaml_show)
			if self.exceptions:
				raise LUTFError("No routes configured")
			return False, [count, num, network, gateway, hop, prio]
		return True, None

	def api_config_rtr_buffers(self, tiny=-1, small=-1, large=-1):
		rc, yaml_err = lnetconfig.lustre_lnet_config_buffers(tiny, small, large, -1)
		err = lnetconfig.cYAML_dump(yaml_err)
		self.cYAML_free(yaml_err)
		if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
			if self.exceptions:
				raise LUTFError("Failed to configure the buffers")
			return False, [rc, err]
		return True, None

	def api_set_routing(self, enable):
		rc, yaml_err = lnetconfig.lustre_lnet_enable_routing(enable, -1)
		logging.debug("rc = %d" % rc)
		err = lnetconfig.cYAML_dump(yaml_err)
		logging.debug(err)
		self.cYAML_free(yaml_err)
		if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
			if self.exceptions:
				raise LUTFError("Failed to set routing")
			return False, [rc, err]
		return True, None

	def api_check_rtr_buffers(self, tiny=LNET_NRB_TINY, small=LNET_NRB_SMALL, large=LNET_NRB_LARGE):
		rc, yaml_show, yaml_err = lnetconfig.lustre_lnet_show_routing(-1, False)
		err = lnetconfig.cYAML_dump(yaml_err)
		show = lnetconfig.cYAML_dump(yaml_show)
		self.cYAML_free(yaml_err)
		self.cYAML_free(yaml_show)
		if rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR:
			if self.exceptions:
				raise LUTFError("Couldn't configure router buffers: %d, %d, %d" % (tiny, small, large))
			return False, [rc, err]
		pyshow = yaml.load(show, Loader=yaml.FullLoader)
		if pyshow['buffers']['tiny'] != tiny or \
		   pyshow['buffers']['small'] != small or \
		   pyshow['buffers']['large'] != large:
			if self.exceptions:
				raise LUTFError("rtr buffer values configured do not match %d != %d, %d != %d, %d != %d" %
				    (pyshow['buffers']['tiny'], tiny, pyshow['buffers']['small'], small,
				     pyshow['buffers']['large'], large))
			return False, [rc, pyshow]
		return True, [rc, pyshow]

	def replace_sep(self, nidstr, old, new):
		bracket = 0
		for i in range(0, len(nidstr)):
			if nidstr[i] == '[':
				bracket += 1
			elif nidstr[i] == ']':
				bracket -= 1
			elif nidstr[i] == old and bracket == 0:
				tmp = list(nidstr)
				tmp[i] = new
				nidstr = "".join(tmp)
		return nidstr

	def api_verify_peer(self, prim_nid, nids):
		rc, yaml_show, yaml_err = lnetconfig.lustre_lnet_show_peer(prim_nid, 4, -1, False)
		err = lnetconfig.cYAML_dump(yaml_err)
		self.cYAML_free(yaml_err)
		try:
			show = lnetconfig.cYAML_dump(yaml_show)
			self.cYAML_free(yaml_show)
		except:
			show = ''
		if rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR:
			if self.exceptions:
				raise LUTFError("Couldn't show peer %s" % (prim_nid))
			pyerr = yaml.load(err, Loader=yaml.FullLoader)
			return False, [rc, pyerr]
		nidlist = []
		if nids:
			nids = self.replace_sep(nids, ',', ' ')
			nidl = lnetconfig.lutf_parse_nidlist(nids, len(nids),
				lnetconfig.LNET_MAX_NIDS_PER_PEER)
			for n in nidl:
				nidlist.append(lnetconfig.lutf_nid2str(n))
		pyshow = yaml.load(show, Loader=yaml.FullLoader)
		if prim_nid:
			nidlist.insert(0, prim_nid)
		nids_found = []
		for nid in nidlist:
			for peerni in pyshow['peer'][0]['peer ni']:
				if peerni['nid'] == nid:
					nids_found.append(nid)
					break;
		return True, [rc, nidlist, nids_found]

	def api_config_peer(self, prim_nid=None, nids=None, is_mr=True):
		rc, yaml_err = lnetconfig.lustre_lnet_modify_peer(prim_nid, nids, is_mr, lnetconfig.LNETCTL_ADD_CMD, -1)
		if rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR:
			err = lnetconfig.cYAML_dump(yaml_err)
			self.cYAML_free(yaml_err)
			if self.exceptions:
				raise LUTFError("Couldn't configure peer %s: %s" % (prim_nid+' '+nids, err))
			pyerr = yaml.load(err, Loader=yaml.FullLoader)
			return False, [rc, pyerr]
		# verify config
		if prim_nid:
			key = prim_nid
		else:
			mynids = self.replace_sep(nids, ',', ' ')
			nidl = lnetconfig.lutf_parse_nidlist(mynids, len(mynids),
			    lnetconfig.LNET_MAX_NIDS_PER_PEER)
			key = lnetconfig.lutf_nid2str(nidl[0])
		rc, info = self.api_verify_peer(key, nids)
		if rc == False:
			if self.exceptions:
				raise LUTFError("Couldn't verify peer " + key)
			return rc, info
		# expect that the NIDs found is the same as the ones we're looking for
		if info[1] !=  info[2]:
			if self.exceptions:
				raise LUTFError("Configured nids are in correct" + key)
			return False, info
		return True, None

	def api_del_peer(self, prim_nid=None, nids=None, all=True):
		rc, yaml_err = lnetconfig.lustre_lnet_modify_peer(prim_nid, nids, False,
			lnetconfig.LNETCTL_DEL_CMD, -1)
		if rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR:
			err = lnetconfig.cYAML_dump(yaml_err)
			if self.exceptions:
				raise LUTFError("Couldn't del peer %s:%d" % (prim_nid, rc))
			pyerr = yaml.load(err, Loader=yaml.FullLoader)
			return False, [rc, pyerr]
		self.cYAML_free(yaml_err)
		# verify config
		try:
			rc, info = self.api_verify_peer(prim_nid, nids)
			if rc and not all:
				# verify that all the peers indicated are gone, excluding the primary nid
				nidlist = info[1]
				foundlist = info[2]
				for n in nidlist[1:]:
					if n in foundlist:
						if self.exceptions:
							raise LUTFError("nid %s wasn't deleted" % (n))
						return False, info
			elif rc:
				if self.exceptions:
					raise LUTFError("Peer %s was not deleted" % (prim_nid))
				return False, [rc, info]
		except:
			if not all:
				if self.exceptions:
					raise LUTFError("Peer %s was not deleted properly" % (prim_nid))
				return False, [rc, info]
			pass
		return True, None

	def api_yaml_cfg(self, yaml_file, count, del_count=0, delete = True):
		logging.debug("configuring yaml file %s" % yaml_file)
		rc, yaml_err = lnetconfig.lustre_yaml_config(yaml_file)
		err = lnetconfig.cYAML_dump(yaml_err)
		self.cYAML_free(yaml_err)
		if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
			logging.debug("config failed with: %d \n%s" % (rc, err))
			if self.exceptions:
				raise LUTFError("configuration failed")
			return False, [rc, err]

		rc, yaml_show, yaml_err = lnetconfig.lustre_yaml_show(yaml_file)
		#rc, yaml_show, yaml_err = lnetconfig.lustre_lnet_show_net(None, 0, -1, False)
		self.cYAML_free(yaml_err)
		if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
			logging.debug(lnetconfig.cYAML_dump(yaml_show))
			err = lnetconfig.cYAML_dump(yaml_err)
			return False, [rc, err]

		show = lnetconfig.cYAML_dump(yaml_show)
		pyy = yaml.load(show, Loader=yaml.FullLoader)
		show_count = 0
		for k, v in pyy.items():
			logging.debug("key = %s, value = %s, len = %d" % (str(k), str(v), len(v)))
			show_count += len(v)
		#show_count = self.cYAML_count(show)
		logging.debug("show count = %d\n%s" % (show_count, show))

		# verify the show through the count only
		self.cYAML_free(yaml_show)
		if (show_count != count):
			error = "show count doesn't match. %d != %d\n%s" % (show_count, count, show)
			logging.debug(error)
			if self.exceptions:
				raise LUTFError(error)
			return False, [rc, show]

		if (delete == True):
			logging.debug("deleting yaml file: %s" % yaml_file)
			rc, yaml_err = lnetconfig.lustre_yaml_del(yaml_file)
			err = lnetconfig.cYAML_dump(yaml_err)
			self.cYAML_free(yaml_err)
			if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
				if self.exceptions:
					raise LUTFError("configuration failed")
				return False, [rc, err]

			logging.debug("showing after deleting yaml file: %s" % yaml_file)
			rc, yaml_show, yaml_err = lnetconfig.lustre_yaml_show(yaml_file)
			err = lnetconfig.cYAML_dump(yaml_err)
			self.cYAML_free(yaml_err)
			if (rc != lnetconfig.LUSTRE_CFG_RC_NO_ERR):
				if self.exceptions:
					raise LUTFError("configuration failed")
				return False, [rc, err]

			# verify the show through the count only
			logging.debug("yaml_show type is %s" % str(type(yaml_show)))
			# handle two cases:
			#  yaml_show is NULL or an empty tree
			if yaml_show == None:
				return True, None
			show = lnetconfig.cYAML_dump(yaml_show)
			pyy = yaml.load(show, Loader=yaml.FullLoader)
			show_count = 0
			for k, v in pyy.items():
				show_count += len(v)
			self.cYAML_free(yaml_show)
			if (show_count != del_count):
				error = "show count doesn't match. %d != %d\n%s" % (show_count, del_count, show)
				logging.debug(error)
				if self.exceptions:
					raise LUTFError(error)
				return False, [rc, show]

		return True, None

	def import_config(self, data):
		L = TheLNet()
		L.import_config(data)

	def import_del(self, data):
		L = TheLNet()
		L.import_del(data)

	def discover(self, nid):
		L = TheLNet()
		rc = L.discover(nid)
		nids = []
		if 'manage' in list(rc.keys()):
			return []
		for entry in rc['discover']:
			for nid in entry['peer ni']:
				nids.append(nid['nid'])
		return nids

	def ping(self, nid):
		L = TheLNet()
		rc = L.ping(nid)
		nids = []
		if 'manage' in list(rc.keys()):
			return []
		for entry in rc['ping']:
			for nid in entry['peer ni']:
				nids.append(nid['nid'])
		return nids

	def get_nets(self, net=None, wrapper=False, detail=False):
		L = TheLNet()
		if not wrapper:
			if detail:
				return L.get_net_detail(net)
			return L.get_net(net)
		else:
			L.update()
			return L.nets[net].get()

	def get_net_stats(self, net=None):
		L = TheLNet()
		return L.get_net_stats(net)

	def get_peers(self, nid=None, detailed=False):
		L = TheLNet()
		if not detailed:
			return L.get_peers(nid=nid)
		return L.get_peers_detail(nid=nid)

	def get_peer_stats(self, nid=None):
		L = TheLNet()
		return L.get_peer_stats(nid=nid)

	def get_stats(self):
		L = TheLNet()
		return L.get_stats()

	def set_discovery(self, value):
		L = TheLNet()
		L.set_global_param('discovery', value)

	def set_max_intf(self, value):
		L = TheLNet()
		L.set_global_param('max_interfaces', value)

	def set_numa_range(self, value):
		L = TheLNet()
		L.set_global_param('numa_range', value)

	def set_drop_asym_route(self, value):
		L = TheLNet()
		L.set_global_param('drop_asym_route', value)

	def set_retry_count(self, value):
		L = TheLNet()
		L.set_global_param('retry_count', value)

	def set_transaction_timeout(self, value):
		L = TheLNet()
		L.set_global_param('transaction_timeout', value)

	def set_health_sensitivity(self, value):
		L = TheLNet()
		L.set_global_param('health_sensitivity', value)

	def set_recovery_interval(self, value):
		L = TheLNet()
		L.set_global_param('recovery_interval', value)

	def set_router_sensitivity(self, value):
		L = TheLNet()
		L.set_global_param('router_sensitivity', value)

	def get_globals(self):
		L = TheLNet()
		return L.get_global()

	def get_config(self):
		L = TheLNet()
		return L.get_config()

	def configure_yaml(self, yml):
		L = TheLNet()
		L.configure_yaml(yml)

	def get_cpu_partition_distance(self):
		p = {}
		cptd = os.path.join(os.sep, 'sys', 'kernel', 'debug', 'lnet', 'cpu_partition_distance')
		if not os.path.isfile(cptd):
			return p
		rc = lutf_exec_local_cmd(CAT + " " + cptd)
		p = yaml.load(rc[0].decode('utf-8').replace('\t', ' '),
			      Loader=yaml.FullLoader)
		for k, v in p.items():
			l = v.split()
			d = {}
			for e in l:
				entry = e.split(':')
				d[int(entry[0])] = int(entry[1])
			p[k] = d
		return p

	def check_udsp_present(self):
		rc = lutf_exec_local_cmd(MAN + " lnetctl")
		ret_str = str(rc)
		if "UDSP" in ret_str:
			return True
		return False

	def cleanup_udsp(self, num_rules=1):
		for ii in range (0, num_rules):
			rc = lutf_exec_local_cmd(get_lnetctl() + " udsp del --idx 0")
		return rc

	def check_udsp_empty(self):
		rc = lutf_exec_local_cmd(get_lnetctl() + " udsp show")
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		print(y)
		if y != None:
			#print("UDSP list not empty")
			error = "UDSP list not empty"
			logging.debug(error)
			return False
		else:
			return True

	def check_udsp_expected(self, udsp_conf_expected_dict):
		rc = lutf_exec_local_cmd(get_lnetctl() + " udsp show")
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		print(y)
		#print ("Out")
		#print(rc[0])
		if y == udsp_conf_expected_dict:
			return True
		else:
			error = "%s doesn't match expected: %s" % (str(y), str(udsp_conf_expected_dict))
			#print("%s doesn't match expected: %s ", str(y), str(udsp_conf_expected_dict))
			logging.debug(error)
		return False

	def exec_udsp_cmd(self, udsp_cmd_string):
		rc = lutf_exec_local_cmd(get_lnetctl() + " udsp " + udsp_cmd_string)
		return rc

	def exec_ping(self, dest_nid):
		rc = lutf_exec_local_cmd(get_lnetctl() + " ping " + dest_nid)
		ret_str = str(rc)
		if "primary nid" in ret_str:
			return True
		return False

	def exec_route_cmd(self, route_cmd):
		rc = lutf_exec_local_cmd(get_lnetctl() + " route " + route_cmd)
		return rc

	def exec_discover_cmd(self, nid):
		rc = lutf_exec_local_cmd(get_lnetctl() + " discover " + nid)
		y = yaml.load(rc[0].decode('utf-8'), Loader=yaml.FullLoader)
		nids = []
		if 'manage' in list(y.keys()):
			return []
		for entry in y['discover']:
			for nid in entry['peer ni']:
				nids.append(nid['nid'])
		return nids
