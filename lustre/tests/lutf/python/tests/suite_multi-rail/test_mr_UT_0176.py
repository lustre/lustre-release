"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- add tcp
- add peers on tcp using the API
- validate peers are multi-rail
- send traffic over the peer NI
- delete the peers
- validate peers recreated are non multi-rail
"""

import os
import yaml, random, threading, time
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lutf_file import LutfFile
from lnet_selftest import LNetSelfTest

def run_lnet_traffic(st1, src, dst):
	st1.start(src, dst)

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
		nids = ','.join(peer_nids2[1:])
		t1.api_config_peer(prim_nid=peer_nids2[0], nids=nids)
		nids = ','.join(peer_nids1[1:])
		t2.api_config_peer(prim_nid=peer_nids1[0], nids=nids)
		# check peer is multi-rail
		peer = t1.get_peers(nid=peer_nids2[0])
		if not peer['peer'][0]['Multi-Rail']:
			return lutfrc(LUTF_TEST_FAIL, "Peer should've been multi-rail", peer=peer)
		st1.load()
		st2.load()
		# start a thread for traffic
		traffic = threading.Thread(target=run_lnet_traffic, args=(st1, peer_nids1[0], peer_nids2[0]))
		traffic.start()
		time.sleep(5)
		# delete the peer on t1
		t1.api_del_peer(prim_nid=peer_nids2[0])
		time.sleep(5)
		peer = t1.get_peers(nid=peer_nids2[0])
		if peer['peer'][0]['Multi-Rail']:
			traffic.join()
			return lutfrc(LUTF_TEST_FAIL, "Peer shouldn't been multi-rail", peer=peer)
		traffic.join()
		st1.unload()
		st2.unload()
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t1.uninit()
		t2.uninit()
		raise e

