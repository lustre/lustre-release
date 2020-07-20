"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- add peer 1 with 2 NIs to tcp1 using the API
- validate peer is correct
- delete a non-existent NID.
- should fail
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
		try:
			t.api_del_peer(prim_nid='192.168.1.11@tcp', nids='192.168.1.6@tcp')
		except:
			return lutfrc(LUTF_TEST_PASS)
		return lutfrc(LUTF_TEST_FAIL, "Was able to delete a non existent peer nid")
	except Exception as e:
		t.uninit()
		raise e

