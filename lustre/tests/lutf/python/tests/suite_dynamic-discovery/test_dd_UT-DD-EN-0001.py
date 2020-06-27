"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: - MR Node with more than two interface, P1..Pn
- MR Peers with more than one interface
- Ping all the peers from the node
- Verify that node sees different peers per NID
- Discover all the peers' first NID from the node
- Verify that node sees one MR peer with all its NIDS
"""

import os
import yaml, random
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lutf_file import LutfFile

def run():
	la = agents.keys()
	if len(la) < 2:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	helpers = []
	try:
		# configure all the nodes
		for i in range(0, len(la)):
			t = LNetHelpers(target=la[i])
			intfs = t.get_available_devs()
			if len(intfs) < 2:
				return lutfrc(LUTF_TEST_SKIP, "Not enough interfaces")
			t.configure_lnet()
			t.configure_net('tcp', intfs)
			t.set_discovery(1)
			helpers.append(t)

		# ping all the nodes from main
		main = helpers[0]
		main_prim_nid = main.list_nids()[0]
		total_nids = 0
		for i in range(1, len(helpers)):
			actual_nids = helpers[i].list_nids()
			total_nids += len(actual_nids)
			for nid in actual_nids:
				if len(main.ping(nid)) == 0:
					return lutfrc(LUTF_TEST_FAIL, "unable to ping" ,
						target=nid)

		# check that the peers created
		peers = main.get_peers()
		if len(peers['peer']) != total_nids:
			return lutfrc(LUTF_TEST_FAIL, "1. unexpected number of peers" ,
					peers=peers, expected_num_peers=len(peers), actual_num_peers=total_nids)
		prim_nids = []
		for peer in peers['peer']:
			prim_nids.append(peer['primary nid'])
		for i in range(1, len(helpers)):
			actual_nids = helpers[i].list_nids()
			for nid in actual_nids:
				if not nid in prim_nids:
					return lutfrc(LUTF_TEST_FAIL, "unexpected peer set" ,
						actual_nids=actual_nids, prim_nids=prim_nids)

		# discover all the peers from main
		for i in range(1, len(helpers)):
			actual_nids = helpers[i].list_nids()
			if len(main.discover(actual_nids[0])) == 0:
				return lutfrc(LUTF_TEST_FAIL, "unable to discover" ,
					target=actual_nids[0])

		# make sure the peers is what we'd expect
		peers = main.get_peers()
		if len(peers['peer']) != len(helpers) - 1:
			return lutfrc(LUTF_TEST_FAIL, "2. unexpected number of peers" ,
					peers=peers, expected_num_peers=len(peers), actual_num_peers=len(helpers)-1)
		for i in range(1, len(helpers)):
			actual_nids = helpers[i].list_nids()
			for peer in peers['peer']:
				if peer['primary nid'] == actual_nids[0] and \
				   len(peer['peer ni']) != len(actual_nids):
					return lutfrc(LUTF_TEST_FAIL, "3. unexpected number of peers",
							peers=peers, peer_nids=actual_nids)
				elif peer['primary nid'] == actual_nids[0]:
					for ni in peer['peer ni']:
						if not ni['nid'] in actual_nids:
							return lutfrc(LUTF_TEST_FAIL, "unexpected peer nid",
								unkown_nid=ni['nid'], actual_nids=actual_nids)

		for h in helpers:
			h.unconfigure_lnet()

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		for h in helpers:
			h.uninit()
		raise e

