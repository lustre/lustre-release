"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: Test standard route add
1. Configure LNet with a tcp network and one interface
2. Add 9 routes with different remote nets, hops and prios
3. Verify that correct number of routes are configured via the show liblnetconfig API
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
	if len(la) < 2:
		return lutfrc(LUTF_TEST_SKIP, "No agents to run test")

	try:
		t = LNetHelpers(script=os.path.abspath(__file__), target=la[0])
		rtr = LNetHelpers(script=os.path.abspath(__file__), target=la[1])
		t.configure_net('tcp')
		rtr.configure_net('tcp')
		rtr_nids = rtr.list_nids()
		if len(rtr_nids) < 1:
			return lutfrc(LUTF_TEST_FAIL, "No NIDS available for rtr")
		for i in range(1, 10):
			t.api_configure_route('tcp'+str(i), rtr_nids[0], i, i-1)
		# check that there are at least 5 routes configured
		t.api_check_route(9)
		# check that there is 1 route configured with tcp6
		t.api_check_route(1, network='tcp6')
		# check that there is 1 route configured with hop == 5
		t.api_check_route(1, hop=5)
		# check that there is 1 route configure with prio = 5
		t.api_check_route(1, prio=5)
		# check that there is 1 route with tcp6 and gw
		t.api_check_route(1, network='tcp6', gateway=rtr_nids[0])
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		rtr.uninit()
		raise e

