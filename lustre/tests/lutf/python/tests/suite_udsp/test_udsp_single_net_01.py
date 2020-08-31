"""
@PRIMARY: N/A
@PRIMARY_DESC: Verify that local nid can be prioritized for sending via UDSP
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE:
- configure one lnet and more than one nid
- turn on LNet discovery
- run lnetctl discover
- verify that udsp list is empty
- add udsp rule that gives one of the local nids higher priority
- get lnet stats (lnetctl net show -v 4)
- generate traffic by running lnetctl ping multiple times
- get lnet stats again
- verify that all sends were done using the prioritized nid
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
MIN_IFS_PER_NODE = 2
PING_TIMES = 10
PING_NID_NUM = 0
LOCAL_NET = 'tcp'
USE_NID_NUM = 0

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

		rc = main.lh.check_udsp_empty()
		if not rc:
			print("UDSP list not empty")
			return lutfrc(LUTF_TEST_FAIL)
		rc = main.lh.exec_udsp_cmd(" add --src "+main_nids[USE_NID_NUM])
		#rc = main.lh.exec_udsp_cmd("

		before_stats_main = main.sln.get_lnet().get_net_stats()
		print(before_stats_main)

		for i in range(0, PING_TIMES):
			rc = main.lh.exec_ping(agent_nids[PING_NID_NUM])
			if not rc:
				print("ping failed")
				return lutfrc(LUTF_TEST_FAIL)

		after_stats_main = main.sln.get_lnet().get_net_stats()
		print(after_stats_main)

		send_count_before = -1
		send_count_after = -1
		for x in before_stats_main:
			if (x['net type'] == LOCAL_NET):
				for y in x['local NI(s)']:
					if y['nid'] == main_nids[USE_NID_NUM]:
						send_count_before = y['statistics']['send_count']
		for x in after_stats_main:
			if (x['net type'] == LOCAL_NET):
				for y in x['local NI(s)']:
					if y['nid'] == main_nids[USE_NID_NUM]:
						send_count_after = y['statistics']['send_count']
		if send_count_before < 0 or send_count_after < 0:
			print("failed to parse net stats")
			return lutfrc(LUTF_TEST_FAIL)

		if send_count_after - send_count_before < PING_TIMES:
			print("Unexpected number of sends: ", send_count_after - send_count_before)
			return lutfrc(LUTF_TEST_FAIL)

		for n in nodes:
			n.lh.unconfigure_lnet()

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		for n in nodes:
			n.lh.uninit()
		raise e

