"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. Enable routing
2. Configure buffers to default
3. Verify values configured
4. Configure buffers to something other than default
5. Verify values configured
6. disable routing
7. renable routing
8. verify values are back to the defaults
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
	t = LNetHelpers(target=la[0])
	try:
		mem_available = t.get_mem_info().total / (1000 ** 3)
		if mem_available < 3:
			msg = "MEM available %0.2fGB but need at least 3GB" % mem_available
			return lutfrc(LUTF_TEST_SKIP, msg=msg)
		t.configure_lnet()
		t.api_set_routing(True)
		t.api_config_rtr_buffers()
		t.api_check_rtr_buffers()
		t.api_config_rtr_buffers(tiny=8192, small=32768, large=2048)
		t.api_check_rtr_buffers(tiny=8192, small=32768, large=2048)
		t.api_set_routing(False)
		t.api_set_routing(True)
		t.api_config_rtr_buffers()
		t.api_check_rtr_buffers()
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

