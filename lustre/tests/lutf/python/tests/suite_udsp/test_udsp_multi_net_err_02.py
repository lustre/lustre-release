"""
@PRIMARY: N/A
@PRIMARY_DESC: Verify that deleting prioritized local net results no issues
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE:
- configure two networks, multiple nids per network
- add udsp rule that gives highest priority to one of the networks
- generate traffic
- verify that the prioritized network is used
- delete the prioritized network
- generate traffic
- verify that the remaining network is used
"""

import os
import yaml
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lustre_node import SimpleLustreNode

MIN_NODES = 2
MIN_IFS_PER_NODE = 4
PING_TIMES = 10
PING_NID_NUM = 0
LOCAL_NETS = ['tcp', 'tcp1']
USE_NET_NUM = [1]
PRIO_NET = "tcp1"
EXP_UDSP_SHOW = {'udsp': [{'idx': 0, 'src': 'tcp1', 'dst': 'NA', 'rte': 'NA', 'action': {'priority': 0}}]}

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
	if len(la) < MIN_NODES:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	nodes = []
	try:
		for i in range(0, MIN_NODES):
			node = TestLustreTraffic(la[i])
			t = node.lh
			intfs = t.get_available_devs()
			if len(intfs) < MIN_IFS_PER_NODE:
				return lutfrc(LUTF_TEST_SKIP, "Not enough interfaces")
			t.configure_lnet()
			if not t.check_udsp_present():
				return lutfrc(LUTF_TEST_SKIP, "UDSP feature is missing")
			for j, net in enumerate(LOCAL_NETS):
				half = len(intfs)//len(LOCAL_NETS)
				net_intfs_list = intfs[half*(j):half*(j+1)]
				t.configure_net(net, net_intfs_list)
			t.set_discovery(1)
			nodes.append(node)

		main = nodes[1]
		main_nids = main.lh.list_nids()
		agent = nodes[0]
		agent_nids = agent.lh.list_nids()

		# discover all the peers from main
		if len(main.lh.discover(agent_nids[0])) == 0:
			return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
				target=agent_nids[0])

		rc = main.lh.check_udsp_empty()
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "UDSP list not empty")

		# Prioritize one of the nets
		rc = main.lh.exec_udsp_cmd(" add --src "+PRIO_NET)
		# Verify the rule got added
		rc = main.lh.check_udsp_expected(EXP_UDSP_SHOW)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "adding UDSP rule failed")

		before_stats_main = main.lh.get_net_stats()
		#print(before_stats_main)

		for i in range(0, PING_TIMES):
			rc = main.lh.exec_ping(agent_nids[PING_NID_NUM])
			if not rc:
				return lutfrc(LUTF_TEST_FAIL, "ping failed")

		after_stats_main = main.lh.get_net_stats()
		#print(after_stats_main)

		send_count_before = {}
		send_count_after = {}
		total_send_count_before = 0
		total_send_count_after = 0
		for net_num in USE_NET_NUM:
			send_count_before[net_num] = getStatNet(before_stats_main, LOCAL_NETS, net_num, 'send_count')
			total_send_count_before += send_count_before[net_num]
			send_count_after[net_num] = getStatNet(after_stats_main, LOCAL_NETS, net_num, 'send_count')
			total_send_count_after += send_count_after[net_num]

		#print(send_count_before, send_count_after)

		# Check stats:
		# 1) expect the total send_count to be no less than the number of pings issued
		# 2) expect the send count to increase by the number of pings issued on the preferred net
		if (total_send_count_after - total_send_count_before) < PING_TIMES:
			return lutfrc(LUTF_TEST_FAIL, "total send count mismatch")

		for net_num in USE_NET_NUM:
			if abs(send_count_after[net_num] - send_count_before[net_num]) < PING_TIMES:
				print("send count increase on network ", LOCAL_NETS[net_num],
			      	      " insufficient. Expected ", PING_TIMES, " got ",
				      abs(send_count_after[net_num] - send_count_before[net_num]))
				return lutfrc(LUTF_TEST_FAIL, "send count increase insufficient")

		main.lh.unconfigure_net(PRIO_NET)

		before_stats_main = main.lh.get_net_stats()
		#print(before_stats_main)

		for i in range(0, PING_TIMES):
			rc = main.lh.exec_ping(agent_nids[PING_NID_NUM])
			if not rc:
				return lutfrc(LUTF_TEST_FAIL, "ping failed")

		after_stats_main = main.lh.get_net_stats()
		#print(after_stats_main)

		# Use remaining net
		USE_NET_NUM[0] = 0

		send_count_before = {}
		send_count_after = {}
		total_send_count_before = 0
		total_send_count_after = 0
		for net_num in USE_NET_NUM:
			send_count_before[net_num] = getStatNet(before_stats_main, LOCAL_NETS, net_num, 'send_count')
			total_send_count_before += send_count_before[net_num]
			send_count_after[net_num] = getStatNet(after_stats_main, LOCAL_NETS, net_num, 'send_count')
			total_send_count_after += send_count_after[net_num]

		#print(send_count_before, send_count_after)

		# Check stats:
		# 1) expect the total send_count to be no less than the number of pings issued
		# 2) expect the send count to increase by the number of pings issued on the preferred net
		if (total_send_count_after - total_send_count_before) < PING_TIMES:
			return lutfrc(LUTF_TEST_FAIL, "total send count mismatch")

		for net_num in USE_NET_NUM:
			if abs(send_count_after[net_num] - send_count_before[net_num]) < PING_TIMES:
				print("send count increase on network ", LOCAL_NETS[net_num],
					" insufficient. Expected ", PING_TIMES, " got ",
					abs(send_count_after[net_num] - send_count_before[net_num]))
				return lutfrc(LUTF_TEST_FAIL, "send count increase insufficient")
		for n in nodes:
			n.lh.unconfigure_lnet()

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		for n in nodes:
			n.lh.uninit()
		raise e

