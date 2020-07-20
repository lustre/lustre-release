"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- add peer 1 with 2 NIs to tcp1 using the API
- add peer 2 with 3 NIs to tcp1 using the API
- validate peer is correct
- check ref count on the NIs in peer 1 and 2 == 2
- check credits == 0
- add tcp1.
- check ref count on the NIs in peer 1 and 2 == 1
- check credits != 0
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

def check_peer_info(nid, t, refcount, credits):
	peer = t.get_peers(nid=nid, detailed=True)
	for e in peer['peer']:
		for peerni in e['peer ni']:
			if (peerni['refcount'] != refcount and peerni['nid'] != nid) or peerni['max_ni_tx_credits'] != credits:
				return False, peer
	return True, peer

def run():
	la = agents.keys()
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	t = LNetHelpers(target=la[0])
	try:
		rc = True
		t.configure_lnet()
		t.api_config_peer(prim_nid='192.168.1.11@tcp1', nids='192.168.1.[2-3]@tcp1')
		t.api_config_peer(prim_nid='192.168.122.11@tcp1', nids='192.168.122.[2-4]@tcp1')
		rc, peer = check_peer_info('192.168.1.11@tcp1', t, 2, 0)
		if not rc:
			lutfrc(LUTF_TEST_FAIL, "peer refcount(2) and peer credits(0) are wrong", peer=peer)
		rc, peer = check_peer_info('192.168.122.11@tcp1', t, 2, 0)
		if not rc:
			lutfrc(LUTF_TEST_FAIL, "peer refcount(2) and peer credits(0) are wrong", peer=peer)
		intfs = t.get_available_devs()
		t.configure_net('tcp1')
		rc, peer = check_peer_info('192.168.1.11@tcp1', t, 1, 128)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "peer refcount(1) and peer credits(8) are wrong", peer=peer)
		rc, peer = check_peer_info('192.168.122.11@tcp1', t, 1, 128)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "peer refcount(1) and peer credits(8) are wrong", peer=peer)
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

