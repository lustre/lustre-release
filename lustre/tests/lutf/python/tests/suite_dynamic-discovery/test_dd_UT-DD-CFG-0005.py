"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. set max_intf uing lnetct
2. Grab global configuration and check max_intf value
"""

import os
import yaml, random
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers

def run():
	la = agents.keys()
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	t = LNetHelpers(target=la[0])
	try:
		t.configure_lnet()
		intfs = t.get_available_devs()
		t.configure_net('tcp', intfs)
		t.set_max_intf(500)
		cfg = t.get_globals()
		if not cfg['global']['max_intf'] == 500:
			return lutfrc(LUTF_TEST_FAIL, "max_intf wasn't set properly",
					intended_value=500, actual_value=cfg['global']['max_intf'])

		t.unconfigure_lnet()
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

