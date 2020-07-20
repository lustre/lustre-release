"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- Test the syntax through multiple different peer adds
- add a peer with one NI using the API
- show the peer
- validate peer is correct
- delete the peer using the API
- add the peer again using YAML
- validate peer is correct
- delete the peer using YAML
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
		# TODO test proper syntax
		t.api_config_peer(prim_nid='192.168.122.11@tcp', nids='192.168.0.[12-15]@tcp')
		t.api_del_peer(prim_nid='192.168.122.11@tcp')
		#----

		try:
			rc, info = t.api_config_peer(nids='192.168.0.[12-15]@tcp')
			t.api_del_peer(prim_nid='192.168.0.12@tcp')
		except:
			rc = False
			info = []
			pass
		if rc:
			return lutfrc(LUTF_TEST_FAIL, "Empty primary NID succeeded. Expected failure.", info=info)
		#----
		t.api_config_peer(prim_nid='192.168.0.12@tcp', nids='192.168.0.[12-15]@tcp,192.168.0.16@tcp')
		t.api_del_peer(prim_nid='192.168.0.12@tcp')
		#----
		t.api_config_peer(prim_nid='192.168.0.12@tcp', nids='192.168.0.[12-15,16]@tcp')
		t.api_del_peer(prim_nid='192.168.0.12@tcp')
		#----
		t.api_config_peer(prim_nid='192.168.122.11@tcp', nids='192.168.0.11@tcp,192.168.0.13@tcp,192.168.0.14@tcp')
		t.api_del_peer(prim_nid='192.168.122.11@tcp')
		#----
		try:
			rc, info = t.api_config_peer(prim_nid='', nids='192.168.0.12@tcp,192.168.0.13@tcp,192.168.0.14@tcp')
		except:
			rc = 0
			info = []
			pass
		if rc:
			return lutfrc(LUTF_TEST_FAIL, "Empty primary NID succeeded. Expected failure.", info=info)
		#----
		try:
			t.api_config_peer(prim_nid='192.168.122.[11-12]@tcp', nids='192.168.0.12@tcp,192.168.0.13@tcp,192.168.0.14@tcp')
		except:
			rc = 0
			info = []
			pass
		if rc:
			return lutfrc(LUTF_TEST_FAIL, "Bad primary NID format succeeded. Expected failure.", info=info)
		t.api_config_peer(prim_nid='192.168.0.15@tcp', nids='192.168.0.15@tcp,192.168.0.16@tcp,192.168.0.17@tcp')
		# delete non primary nid
		try:
			rc, info = t.api_del_peer(prim_nid='192.168.17@tcp')
		except:
			rc = 0
			info = []
			pass
		if rc:
			return lutfrc(LUTF_TEST_FAIL, "Deleting non-primary nid succeeded. Expected failure.", info=info)
		t.api_del_peer(prim_nid='192.168.0.15@tcp')

		# configure with bad parameters
		try:
			rc, info = t.api_config_peer()
		except:
			pass
		if rc:
			return lutfrc(LUTF_TEST_FAIL, "Expected failure. Got success.", info=info)
		try:
			rc, info = t.api_config_peer(prim_nid='192.168.122.11@tcpX')
		except:
			pass
		if rc:
			return lutfrc(LUTF_TEST_FAIL, "configuring peer with bad net succeeded. Expected failure", info=info)
		try:
			rc, info = t.api_config_peer(prim_nid='192.168.122.11@tcp', nids='192.168.0.12@tcp,192.168.0.13@tcp,192.168.0.14@tcpX')
		except:
			pass
		if rc:
			return lutfrc(LUTF_TEST_FAIL, "configuring peer with bad net succeeded. Expected failure", info=info)
		#----
		t.api_config_peer(prim_nid='192.168.122.11@tcp', nids='192.168.0.11@tcp,192.168.0.13@tcp,192.168.0.14@tcp')
		peers = t.get_peers()
		t.api_del_peer(prim_nid='192.168.122.11@tcp')
		t.import_config(peers)
		peers2 = t.get_peers()
		if peers != peers2:
			return lutfrc(LUTF_TEST_FAIL, "peers were not configured properly from YAML", requested=peers, configured=peers2)
		#----
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

