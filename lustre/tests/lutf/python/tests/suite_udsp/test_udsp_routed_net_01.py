"""
@PRIMARY: N/A
@PRIMARY_DESC: Verify that deleting prioritized local net results no issues
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE:
- configure single local network with two nids
- configure two gws each providing access to a remote network
- configure remote peer to have access to the remote network with two nids
- add udsp rule that designates a pair of a router and remote peer nid as preferred
- add udsp rule that gives the same remote peer nid highest priority
- generate traffic
- verify that the preferred remote peer nid an router were used
"""

import os
import yaml
import lnetconfig
import time
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lustre_node import SimpleLustreNode

MIN_NODES = 4
MIN_IFS_PER_NODE = 2
GW_MIN_IFS = 4
PING_TIMES = 10
PING_NID_NUM = 0
LOCAL_NETS = ['tcp']
REMOTE_NETS = ['tcp1']
USE_NET_NUM = [0]
MAIN_NODE_ID = 1
REMOTE_NODE_ID = 3
GW_NODE_IDS = [2, 0]

class TestLustreTraffic:
        def __init__(self, target=None):
                self.lh = LNetHelpers(os.path.abspath(__file__), target=target)
                self.sln = SimpleLustreNode(os.path.abspath(__file__), target=target)


def getStatNIDStr(stats_dict, nid_str, nid_stat_str):
	for x in stats_dict:
		for y in x['local NI(s)']:
			if y['nid'] == nid_str:
				return y['statistics'][nid_stat_str]
	return -1

def getStatNet(stats_dict, net_list, net_num, nid_stat_str):
	stat_val = 0
	for x in stats_dict:
		if (x['net type'] == net_list[net_num]):
			for y in x['local NI(s)']:
					stat_val += y['statistics'][nid_stat_str]
	return stat_val

def getNetNIDbyIdx(stats_dict, net_name, nid_idx):
	nid_str = ""
	for x in stats_dict:
		if (x['net type'] == net_name):
			nid_str = x['local NI(s)'][nid_idx]['nid']
			break
	return nid_str

def run():
	la = agents.keys()
	#if len(la) < MIN_NODES:
	#	return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	nodes = []
	try:
		# General config for all nodes
		for i in range(0, MIN_NODES):
			node = TestLustreTraffic(la[i])
			t = node.lh
			if i in GW_NODE_IDS:
				node_num_ifs = GW_MIN_IFS
			else:
				node_num_ifs = MIN_IFS_PER_NODE
			intfs = t.get_available_devs()
			if len(intfs) < node_num_ifs:
				return lutfrc(LUTF_TEST_SKIP, "Not enough interfaces")
			t.configure_lnet()
			if not t.check_udsp_present():
				return lutfrc(LUTF_TEST_SKIP, "UDSP feature is missing")

			if i == MAIN_NODE_ID:
				# Peer A
				net = LOCAL_NETS[0]
				net_intfs_list = intfs[0:node_num_ifs]
				t.configure_net(net, net_intfs_list)
			elif i == REMOTE_NODE_ID:
				# Peer B
				net = REMOTE_NETS[0]
				net_intfs_list = intfs[0:node_num_ifs]
				t.configure_net(net, net_intfs_list)
			else:
				# GW1 and GW2
				net = LOCAL_NETS[0]
				net_intfs_list = intfs[0:node_num_ifs//2]
				t.configure_net(net, net_intfs_list)
				net = REMOTE_NETS[0]
				net_intfs_list = intfs[node_num_ifs//2:node_num_ifs]
				t.configure_net(net, net_intfs_list)

			t.set_discovery(1)
			nodes.append(node)

		main = nodes[MAIN_NODE_ID]
		main_nids = main.lh.list_nids()
		remote = nodes[REMOTE_NODE_ID]
		remote_nids = remote.lh.list_nids()
		gw1 = nodes[GW_NODE_IDS[0]]
		gw2 = nodes[GW_NODE_IDS[1]]
		gw1_nids = gw1.lh.list_nids()
		gw2_nids = gw2.lh.list_nids()

		#print("main nids: ", main_nids)
		#print("remote nids: ", remote_nids)
		#print("gw1 nids: ", gw1_nids)
		#print("gw2 nids: ", gw2_nids)

		gw1.lh.api_set_routing(True)
		gw2.lh.api_set_routing(True)

		gw1_remote_nids = [x for x in gw1_nids if REMOTE_NETS[0] in x]
		gw1_local_nids = [x for x in gw1_nids if x not in gw1_remote_nids]

		gw2_remote_nids = [x for x in gw2_nids if REMOTE_NETS[0] in x]
		gw2_local_nids = [x for x in gw2_nids if x not in gw2_remote_nids]

		#print("gw1 local/remote nids: ", gw1_local_nids, gw1_remote_nids)
		#print("gw2 local/remote nids: ", gw2_local_nids, gw2_remote_nids)

		# discover the gateways from main and remote
		if len(main.lh.exec_discover_cmd(gw1_local_nids[0])) == 0:
			return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
				target=gw1_local_nids[0])
		if len(main.lh.exec_discover_cmd(gw2_local_nids[0])) == 0:
			return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
				target=gw2_local_nids[0])
		if len(remote.lh.exec_discover_cmd(gw1_remote_nids[0])) == 0:
			return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
				target=gw1_remote_nids[0])
		if len(remote.lh.exec_discover_cmd(gw2_remote_nids[0])) == 0:
			return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
				target=gw2_remote_nids[0])

		# setup the routing
		rt1 = "--net " + REMOTE_NETS[0] + " --gateway " + gw1_local_nids[0]
		rt2 = "--net " + REMOTE_NETS[0] + " --gateway " + gw2_local_nids[0]
		rc = main.lh.exec_route_cmd(" add "+rt1)
		rc = main.lh.exec_route_cmd(" add "+rt2)
		rt1 = "--net " + LOCAL_NETS[0] + " --gateway " + gw1_remote_nids[0]
		rt2 = "--net " + LOCAL_NETS[0] + " --gateway " + gw2_remote_nids[0]
		rc = remote.lh.exec_route_cmd(" add "+rt1)
		rc = remote.lh.exec_route_cmd(" add "+rt2)

		# commit configuration
		#gw1.sln.commit()
		#gw1.lh.api_set_routing(True)
		#time.sleep(1)
		#gw2.sln.commit()
		#gw2.lh.api_set_routing(True)
		#main.sln.commit()
		#remote.sln.commit()
		time.sleep(1)

		rc = main.lh.exec_ping(remote_nids[0])
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "ping failed")

		# let main and remote discover each other
		try:
			if len(main.lh.exec_discover_cmd(remote_nids[0])) == 0:
				return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
					target=remote_nids[0])
		except Exception as e:
			if len(main.lh.exec_discover_cmd(remote_nids[0])) == 0:
				return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
					target=remote_nids[0])
		try:
			if len(remote.lh.exec_discover_cmd(main_nids[0])) == 0:
				return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
					target=main_nids[0])
		except Exception as e:
			if len(remote.lh.exec_discover_cmd(main_nids[0])) == 0:
				return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
					target=main_nids[0])


		rc = main.lh.check_udsp_empty()
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "UDSP list not empty")

		for net_num in USE_NET_NUM:
			# Add UDSP rule on main node to prioritize a nid on remote node
			rc = main.lh.exec_udsp_cmd(" add --dst "+remote_nids[0])
			# Prioritize gw1 for use with the prioritized remote node
			rc = main.lh.exec_udsp_cmd(" add --rte "+\
						   gw1_local_nids[0]+\
						   " --dst "+remote_nids[0])

		before_stats_gw1 = gw1.lh.get_stats()
		#print(before_stats_gw1)

		for i in range(0, PING_TIMES):
			rc = main.lh.exec_ping(remote_nids[PING_NID_NUM])
			if not rc:
				return lutfrc(LUTF_TEST_FAIL, "ping failed")

		after_stats_gw1 = gw1.lh.get_stats()
		#print(after_stats_gw1)

		route_count_before = before_stats_gw1['statistics']['route_count']
		route_count_after = after_stats_gw1['statistics']['route_count']

		#print(route_count_before, route_count_after)

		# Check stats:
		# 1) expect the difference between "before" and "after" route counts to be
		#    same as or greater than the number of pings issued
		if (route_count_after - route_count_before) < PING_TIMES:
			return lutfrc(LUTF_TEST_FAIL, "routed count mismatch")

		for i in range(0, MIN_NODES):
			if i == MAIN_NODE_ID or i == REMOTE_NODE_ID:
				nodes[i].lh.unconfigure_lnet()

		for i in range(0, MIN_NODES):
			if i != MAIN_NODE_ID and i != REMOTE_NODE_ID:
				nodes[i].lh.unconfigure_lnet()
		#for n in nodes:
		#	n.lh.unconfigure_lnet()

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		for n in nodes:
			n.lh.uninit()
		raise e

