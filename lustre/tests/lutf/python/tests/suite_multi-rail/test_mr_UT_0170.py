"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- add peer 1 with 2 NIs using the API
- add peer 2 with 3 NIs using the API
- validate peer is correct
- deinitialize LNet
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
		t.api_config_peer(prim_nid='192.168.1.11@tcp', nids='192.168.1.[2-3]@tcp')
		t.api_config_peer(prim_nid='192.168.122.11@tcp', nids='192.168.122.[2-4]@tcp')
		try:
			t.uninit()
			t.unconfigure_lnet()
		except:
			return lutfrc(LUTF_TEST_FAIL, "Failed to unconfigure lnet with peers configured")
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

