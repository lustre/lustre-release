"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. Allocate nodes: PeerA, PeerB and GW1
2. Configure PeerA with "tcp" net, PeerB with "tcp1" net, GW1 with both
3. Configure GW1 as a router b/w tcp and tcp1 nets.
3. Add routes to PeerA and PeerB so they can reach each other.
4. Execute lnetctl ping several times
5. Retrieve stats on GW1 and verify that it was routing the pings.
6. Clean up.
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
from lutf_cmd import lutf_exec_local_cmd
from utility_paths import LNETCTL

MIN_NODES = 3
MIN_IFS_PER_NODE = 1
GW_MIN_IFS = 2
PING_TIMES = 10
PING_NID_NUM = 0
LOCAL_NETS = ['tcp']
REMOTE_NETS = ['tcp1']
USE_NET_NUM = [0]
MAIN_NODE_ID = 0
REMOTE_NODE_ID = 1
GW_NODE_IDS = [2]

class TestLustreTraffic:
        def __init__(self, target=None):
                self.lh = LNetHelpers(os.path.abspath(__file__), target=target)
                self.sln = SimpleLustreNode(os.path.abspath(__file__), target=target)

def run():
	la = agents.keys()
	if len(la) < MIN_NODES:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	nodes = []
	try:
		# General config for all nodes
		for i in range(0, MIN_NODES):
			node = TestLustreTraffic(la[i])
			t = node.lh
			if i in GW_NODE_IDS:
				node_num_ifs = GW_MIN_IFS
				print("Processing gw node init")
			else:
				node_num_ifs = MIN_IFS_PER_NODE
			intfs = t.get_available_devs()
			print(i, " intfs: ", intfs)
			if len(intfs) < node_num_ifs:
				return lutfrc(LUTF_TEST_FAIL, "Not enough interfaces")
			print("Configure")
			t.configure_lnet()

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
				# GW1
				net = LOCAL_NETS[0]
				net_intfs_list = intfs[0:node_num_ifs//2]
				t.configure_net(net, net_intfs_list)
				net = REMOTE_NETS[0]
				net_intfs_list = intfs[node_num_ifs//2:node_num_ifs]
				t.configure_net(net, net_intfs_list)

			print("Set discovery on")
			t.set_discovery(1)
			print("done")
			nodes.append(node)

		main = nodes[MAIN_NODE_ID]
		main_nids = main.lh.list_nids()
		remote = nodes[REMOTE_NODE_ID]
		remote_nids = remote.lh.list_nids()
		gw1 = nodes[GW_NODE_IDS[0]]
		gw1_nids = gw1.lh.list_nids()

		print("main nids: ", main_nids)
		print("remote nids: ", remote_nids)
		print("gw1 nids: ", gw1_nids)

		gw1.lh.api_set_routing(True)

		gw1_remote_nids = [x for x in gw1_nids if REMOTE_NETS[0] in x]
		gw1_local_nids = [x for x in gw1_nids if x not in gw1_remote_nids]

		print("gw1 local/remote nids: ", gw1_local_nids, gw1_remote_nids)

		# discover the gateway from main and remote nodes
		if len(main.lh.exec_discover_cmd(gw1_local_nids[0])) == 0:
			return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
				target=gw1_local_nids[0])
		if len(remote.lh.exec_discover_cmd(gw1_remote_nids[0])) == 0:
			return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
				target=gw1_remote_nids[0])

		# setup the routing
		rt1 = "--net " + REMOTE_NETS[0] + " --gateway " + gw1_local_nids[0]
		rc = main.lh.exec_route_cmd(" add "+rt1)
		rt1 = "--net " + LOCAL_NETS[0] + " --gateway " + gw1_remote_nids[0]
		rc = remote.lh.exec_route_cmd(" add "+rt1)

		time.sleep(1)

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

		before_stats_gw1 = gw1.lh.get_stats()
		print(before_stats_gw1)

		for i in range(0, PING_TIMES):
			rc = main.lh.exec_ping(remote_nids[PING_NID_NUM])
			if not rc:
				print("ping failed")
				return lutfrc(LUTF_TEST_FAIL)

		after_stats_gw1 = gw1.lh.get_stats()
		print(after_stats_gw1)

		route_count_before = before_stats_gw1['statistics']['route_count']
		route_count_after = after_stats_gw1['statistics']['route_count']

		print(route_count_before, route_count_after)

		# Check stats:
		# 1) expect the difference between "before" and "after" route counts to be
		#    same as or greater than the number of pings issued
		if (route_count_after - route_count_before) < PING_TIMES:
			print("routed count mismatch")
			return lutfrc(LUTF_TEST_FAIL)

		for n in nodes:
			lutf_exec_local_cmd(LNETCTL + " lnet unconfigure")

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		for n in nodes:
			n.lh.uninit()
		raise e

