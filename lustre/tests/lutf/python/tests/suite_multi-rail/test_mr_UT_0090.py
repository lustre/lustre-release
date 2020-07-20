"""
@PRIMARY: cfg-060
@PRIMARY_DESC: lnetctl utility shall provide a command line front end interface to configure local NIs by calling the DLC APIs
@SECONDARY:
@DESIGN: N/A
@TESTCASE:
- Configure a non-existant interface on tcp1
- sanitize this configuration fails with bad parameter
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
		t.configure_lnet()
		try:
			t.api_config_ni('tcp1', ['amir'])
		except:
			t.uninit()
			return lutfrc(LUTF_TEST_PASS)

		return lutfrc(LUTF_TEST_FAIL, "Configured an unknown interface")
	except Exception as e:
		t.uninit()
		raise e

