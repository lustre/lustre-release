"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. Call the lustre_lnet_config_net() function to add a net.
2. missing net param
3. expect MISSING Param return code
"""

import os
import yaml
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers

def run():
	la = agents.keys()
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "No agents to run test")
	try:
		t = LNetHelpers(target=la[0])
		t.configure_lnet()
		intfs = t.get_available_devs()
		t.set_exception(False)
		rc, info = t.api_config_ni('', intfs)
		if rc:
			#expecting failure
			return lutfrc(LUTF_TEST_FAIL, details=info)
		return lutfrc(LUTF_TEST_PASS, details=info)
	except Exception as e:
		t.uninit()
		raise e
