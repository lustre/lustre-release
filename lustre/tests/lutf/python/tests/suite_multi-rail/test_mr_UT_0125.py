"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- add a peer with multiple NI using the API
- store the YAML show to use later
- validate peer is correct
- delete non-primary NIDs one by one using the API
- re-add the exact same peer
- validate
- delete using YAML
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
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	t = LNetHelpers(target=la[0])
	try:
		rc = True
		t.configure_lnet()
		t.api_config_peer(prim_nid='192.168.122.11@tcp', nids='192.168.122.[12-15]@tcp')
		peers = t.get_peers()
		t.api_del_peer(prim_nid='192.168.122.11@tcp', nids='192.168.122.12@tcp', all=False)
		t.api_del_peer(prim_nid='192.168.122.11@tcp', nids='192.168.122.13@tcp', all=False)
		t.api_del_peer(prim_nid='192.168.122.11@tcp', nids='192.168.122.14@tcp', all=False)
		t.api_del_peer(prim_nid='192.168.122.11@tcp', nids='192.168.122.15@tcp', all=False)
		t.api_del_peer(prim_nid='192.168.122.11@tcp')
		t.api_config_peer(prim_nid='192.168.122.11@tcp', nids='192.168.122.[12-15]@tcp')
		peers2 = t.get_peers()
		if peers != peers2:
			return lutfrc(LUTF_TEST_FAIL, "Failed to delete peers configure YAML.", peers=peers2)
		t.import_del(peers)
		peers = t.get_peers()
		if peers and len(peers) > 0:
			return lutfrc(LUTF_TEST_FAIL, "Failed to delete peers via YAML.", peers=peers)
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

