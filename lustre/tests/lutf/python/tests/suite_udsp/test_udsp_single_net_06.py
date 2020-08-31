"""
@PRIMARY: N/A
@PRIMARY_DESC: Verify UDSP nid pair rule in combination with local nid prioritization rule
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE:
- configure one lnet and more than one nid
- turn on LNet discovery
- run lnetctl discover
- verify that udsp list is empty
- add udsp rule that gives one of the local nids higher priority
- add udsp rule that pairs the prioritized local nid with a certain peer nid
- get lnet stats (lnetctl net show -v 4)
- generate traffic by running lnetctl ping multiple times
- get lnet stats again
- verify that the paired destination nid received all pings
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

MIN_IFS_PER_NODE = 3
PING_TIMES = 10
PING_NID_NUM = 0
LOCAL_NET = 'tcp'
USE_NID_NUM = [0]
MIN_NODES = 2
LOCAL_DEBUG = 1

class TestLustreTraffic:
        def __init__(self, target=None):
                self.lh = LNetHelpers(os.path.abspath(__file__), target=target)
                self.sln = SimpleLustreNode(os.path.abspath(__file__), target=target)

def getNetStatNID(stats_dict, nid_list, nid_num, nid_stat_str):
	for x in stats_dict:
		if (x['net type'] == LOCAL_NET):
			for y in x['local NI(s)']:
				if y['nid'] == nid_list[nid_num]:
					return y['statistics'][nid_stat_str]
	return -1

def udsp_print(*args):
	if LOCAL_DEBUG:
		print(args)

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
			if not t.check_udsp_present():
				return lutfrc(LUTF_TEST_SKIP, "UDSP feature is missing")
			t.configure_lnet()
			t.configure_net(LOCAL_NET, intfs)
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
			udsp_print("UDSP list not empty")
			return lutfrc(LUTF_TEST_FAIL)

		for nid_num in USE_NID_NUM:
			rc = main.lh.exec_udsp_cmd(" add --src "+main_nids[nid_num])
			rc = main.lh.exec_udsp_cmd(" add --src "+main_nids[nid_num]+" --dst "+agent_nids[nid_num])
		before_stats_agent = agent.lh.get_net_stats()
		udsp_print(before_stats_agent)

		for i in range(0, PING_TIMES):
			rc = main.lh.exec_ping(agent_nids[PING_NID_NUM])
			if not rc:
				udsp_print("ping failed")
				return lutfrc(LUTF_TEST_FAIL)

		after_stats_agent = agent.lh.get_net_stats()
		udsp_print(after_stats_agent)

		recv_count_before = {}
		recv_count_after = {}
		total_recv_count_before = 0
		total_recv_count_after = 0
		nid_num = 0
		for nid in agent_nids:
			recv_count_before[nid_num] = getNetStatNID(before_stats_agent, agent_nids, nid_num, 'recv_count')
			total_recv_count_before += recv_count_before[nid_num]
			recv_count_after[nid_num] = getNetStatNID(after_stats_agent, agent_nids, nid_num, 'recv_count')
			total_recv_count_after += recv_count_after[nid_num]
			nid_num += 1

		udsp_print(recv_count_before, recv_count_after)

		# Check
		# 1) expect the total recv_count on the agent to be no less than the number of pings issued
		# 2) expect the recv count on the preferred peer interface to increase by the number of pings issues
		if (total_recv_count_after - total_recv_count_before) < PING_TIMES:
			udsp_print("total recv count mismatch")
			return lutfrc(LUTF_TEST_FAIL)

		if abs(recv_count_after[0] - recv_count_before[0]) < PING_TIMES:
			udsp_print("less than expected traffic on the prioritized peer nid")
			return lutfrc(LUTF_TEST_FAIL)

		for n in nodes:
			n.lh.unconfigure_lnet()

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		for n in nodes:
			n.lh.uninit()
		raise e

