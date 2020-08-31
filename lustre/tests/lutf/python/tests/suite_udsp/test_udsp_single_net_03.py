"""
@PRIMARY: N/A
@PRIMARY_DESC: Verify that local nid can be deprioritized for sending via UDSP
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE:
- configure one lnet and more than two nids
- turn on LNet discovery
- run lnetctl discover
- verify that udsp list is empty
- add udsp rule that gives two of the local nids higher priority
- get lnet stats (lnetctl net show -v 4)
- generate traffic by running lnetctl ping multiple times
- get lnet stats again
- verify that all sends were done using the prioritized nids
- delete udsp rule for one of the nids
- generate traffic by running lnetctl ping multiple times
- get lnet stats again
- verify that all sends were done using the remaining prioritized nid
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
MIN_IFS_PER_NODE = 3
PING_TIMES = 10
PING_NID_NUM = 0
LOCAL_NET = 'tcp'
NID_NUM_A = 0
NID_NUM_B = 1
USE_NID_NUM = [NID_NUM_A, NID_NUM_B]

class TestLustreTraffic:
        def __init__(self, target=None):
                self.lh = LNetHelpers(os.path.abspath(__file__), target=target)
                self.sln = SimpleLustreNode(os.path.abspath(__file__), target=target)

def getStatNID(stats_dict, nid_list, nid_num, nid_stat_str):
	for x in stats_dict:
		if (x['net type'] == LOCAL_NET):
			for y in x['local NI(s)']:
				if y['nid'] == nid_list[nid_num]:
					return y['statistics'][nid_stat_str]
	return -1


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
			print("UDSP list not empty")
			return lutfrc(LUTF_TEST_FAIL)

		for nid_num in USE_NID_NUM:
			rc = main.lh.exec_udsp_cmd(" add --src "+main_nids[nid_num])

		before_stats_main = main.sln.get_lnet().get_net_stats()
		print(before_stats_main)

		for i in range(0, PING_TIMES):
			rc = main.lh.exec_ping(agent_nids[PING_NID_NUM])
			if not rc:
				print("ping failed")
				return lutfrc(LUTF_TEST_FAIL)

		after_stats_main = main.sln.get_lnet().get_net_stats()
		print(after_stats_main)

		send_count_before = {}
		send_count_after = {}
		total_send_count_before = 0
		total_send_count_after = 0
		for nid_num in USE_NID_NUM:
			#print({nid_num: getStatNID(before_stats_main, main_nids, nid_num, 'send_count')})
			#print({nid_num: getStatNID(after_stats_main, main_nids, nid_num, 'send_count')})
			send_count_before[nid_num] = getStatNID(before_stats_main, main_nids, nid_num, 'send_count')
			total_send_count_before += send_count_before[nid_num]
			send_count_after[nid_num] = getStatNID(after_stats_main, main_nids, nid_num, 'send_count')
			total_send_count_after += send_count_after[nid_num]

		print(send_count_before, send_count_after)

		# Check stats:
		# 1) expect send counts on both interfaces to increase
		# 2) expect the total send_count to be no less than the number of pings issued
		# 3) expect the send counts on the two interfaces used to be close (diff < 2)
		if (total_send_count_after - total_send_count_before) < PING_TIMES:
			print("total send count mismatch")
			return lutfrc(LUTF_TEST_FAIL)

		if abs(send_count_after[NID_NUM_A] - send_count_after[NID_NUM_B]) > 1:
			print("uneven tx traffic distribution across interfaces")
			return lutfrc(LUTF_TEST_FAIL)

		# Delete the UDSP for the first of the nids
		rc = main.lh.exec_udsp_cmd(" del --idx 0 ")

		# Generate traffic and collect stats
		before_stats_main = main.sln.get_lnet().get_net_stats()
		print(before_stats_main)

		for i in range(0, PING_TIMES):
			rc = main.lh.exec_ping(agent_nids[PING_NID_NUM])
			if not rc:
				print("ping failed")
				return lutfrc(LUTF_TEST_FAIL)

		after_stats_main = main.sln.get_lnet().get_net_stats()
		print(after_stats_main)

		send_count_before = {}
		send_count_after = {}
		total_send_count_before = 0
		total_send_count_after = 0
		for nid_num in USE_NID_NUM:
			#print({nid_num: getStatNID(before_stats_main, main_nids, nid_num, 'send_count')})
			#print({nid_num: getStatNID(after_stats_main, main_nids, nid_num, 'send_count')})
			send_count_before[nid_num] = getStatNID(before_stats_main, main_nids, nid_num, 'send_count')
			total_send_count_before += send_count_before[nid_num]
			send_count_after[nid_num] = getStatNID(after_stats_main, main_nids, nid_num, 'send_count')
			total_send_count_after += send_count_after[nid_num]

		print(send_count_before, send_count_after)

		# Check stats:
		# 1) expect send count on second interface to increase
		# 2) expect the total send_count to be no less than the number of pings issued
		# 3) expect the send count on the preferred interface to increase by no less than the
		#    number of pings issued
		# 4) expect the send count on the preferred interface to be greater than on the other interface
		#	by at least the number of pings less one
		if (total_send_count_after - total_send_count_before) < PING_TIMES:
			print("total send count mismatch")
			return lutfrc(LUTF_TEST_FAIL)

		if abs(send_count_after[NID_NUM_B] - send_count_before[NID_NUM_B]) < PING_TIMES:
			print("send count increase on preferred interface ", NID_NUM_B,
			      " insufficient. Expected ", PING_TIMES, " got",
			      abs(send_count_after[NID_NUM_B] - send_count_before[NID_NUM_B]))
			return lutfrc(LUTF_TEST_FAIL)

		for n in nodes:
			n.lh.unconfigure_lnet()

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		for n in nodes:
			n.lh.uninit()
		raise e

