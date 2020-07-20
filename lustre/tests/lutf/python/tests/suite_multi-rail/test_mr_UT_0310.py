"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- Configure an MR system
- Configure peers via DLC
- Start traffic
- Monitor traffic is being sent to all configured peers
- Delete one of the peer NIs
- Monitor traffic is no longer sent to that peer NI
- No messages should be dropped
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
from lnet_selftest import LNetSelfTest

def run():
	la = agents.keys()
	if len(la) < 2:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	t1 = LNetHelpers(target=la[0])
	st1 = LNetSelfTest(target=la[0])
	t2 = LNetHelpers(target=la[1])
	st2 = LNetSelfTest(target=la[1])
	try:
		t1.configure_lnet()
		t1.configure_net('tcp1')
		t1.set_discovery(0)
		peer_nids1 = t1.list_nids()
		t2.configure_lnet()
		t2.configure_net('tcp1')
		t2.set_discovery(0)
		peer_nids2 = t2.list_nids()
		if len(peer_nids1) < 2 or len(peer_nids2) < 2:
			return lutfrc(LUTF_TEST_SKIP, "Need more than 2 interfaces for this test")
		nids = ','.join(peer_nids2[1:])
		t1.api_config_peer(prim_nid=peer_nids2[0], nids=nids)
		nids = ','.join(peer_nids1[1:])
		t2.api_config_peer(prim_nid=peer_nids1[0], nids=nids)
		st1.load()
		st2.load()
		st1.start(peer_nids1[0], peer_nids2[0])
		st1.unload()
		st2.unload()
		stats = t1.get_peer_stats(peer_nids2[0])
		# verify traffic is distributed across the nis
		range = 50
		first_send = 0
		num_nids = len(peer_nids2)
		count_bad_nids = 0
		for e in stats:
			for lpni in e['peer ni']:
				lpnistats = lpni['statistics']
				if not first_send:
					first_send = lpnistats['send_count']
					if first_send <= 0:
						return lutfrc(LUTF_TEST_FAIL, "no traffic was sent",
							stats=stats)
				else:
					send_count = lpnistats['send_count']
					delta = lpnistats['send_count'] * (range/100)
					upper_range = first_send + delta
					lower_range = first_send - delta
					if send_count > upper_range or send_count < lower_range:
						count_bad_nids += 1
						# tolerate 30 % of the
						# NIDs having send count
						# out of range
						if count_bad_nids <= int(num_nids * 0.3):
							continue
						return lutfrc(LUTF_TEST_FAIL, "Traffic wasn't distributed evenly",
							stats=stats)
		t1.api_del_peer(prim_nid=peer_nids2[0], nids=peer_nids2[1])
		st1.load()
		st2.load()
		st1.start(peer_nids1[0], peer_nids2[0])
		st1.unload()
		st2.unload()
		# check to make sure the peer ni we deleted isn't
		# recreated
		try:
			peers = t1.get_peers(nid=peer_nids2[1])
			return lutfrc(LUTF_TEST_FAIL, "peer on deleted network didn't go away", peer=peers)
		except:
			pass
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t1.uninit()
		t2.uninit()
		raise e

