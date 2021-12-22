"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. Test configuring the same network twice.
2. Verify the second configure fails
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
	t = None
	for agent in la:
		t = LNetHelpers(target=agent)
		if t.can_be_router():
			break
		else:
			t = None
	if not t:
		return lutfrc(LUTF_TEST_SKIP,
			comment="no routers found")
	try:
		t = LNetHelpers(target=agent)
		t.configure_lnet()
		t.api_set_routing(True)
		t.set_exception(False)
		rc, info = t.api_config_rtr_buffers(tiny=-323)
		if rc:
			# expect failure
			return lutfrc(LUTF_TEST_FAIL, details=info)
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

