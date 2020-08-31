"""
@PRIMARY: N/A
@PRIMARY_DESC: Check that udsp rule table is empty on a newly configured lnet
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE:
- check that udsp rule table is empty on a newly configured lnet
"""

import os
import yaml
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lutf_cmd import lutf_exec_local_cmd
from utility_paths import LNETCTL

def check_udsp_empty():
	rc = lutf_exec_local_cmd(LNETCTL + " udsp show")
	if 'idx' in rc[0].decode('utf-8'):
		return False
	else:
		return True

def run():
	la = agents.keys()
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "No agents to run test")
	try:
		t = LNetHelpers(target=la[0])
		t.configure_lnet()
		if not t.check_udsp_present():
			return lutfrc(LUTF_TEST_SKIP, "UDSP feature is missing")
		rc = check_udsp_empty();
		if not rc:
			return lutfrc(LUTF_TEST_FAIL)
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e


