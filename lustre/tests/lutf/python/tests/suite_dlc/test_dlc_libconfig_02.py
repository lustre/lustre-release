"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: Test standard route add
1. Configure LNet with a tcp network and one interface
2. Add a route with no hop, prio or sensitivity specified
3. Add a route with hop but no prio or sensitivity specified
4. Add a route with prio but no hop or sensitivity specified
5. Add a route with sensitivity but no op or prio specified
3. Check configuration is successful after each route configure
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
		# test standard route config
		t.api_configure_route(rnet='tcp2', gw=rtr_nids[0])
		# test configuring hops
		t.api_configure_route(rnet='tcp3', gw=rtr_nids[0], hop=4)
		# test configuring priority
		t.api_configure_route(rnet='tcp4', gw=rtr_nids[0], prio=2)
		# test configuring sensitivity
		t.api_configure_route(rnet='tcp5', gw=rtr_nids[0], sen=100)
		t.api_del_route(rnet='tcp2', gw=rtr_nids[0])
		t.api_del_route(rnet='tcp3', gw=rtr_nids[0])
		t.api_del_route(rnet='tcp4', gw=rtr_nids[0])
		t.api_del_route(rnet='tcp5', gw=rtr_nids[0])
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		rtr.uninit()
		raise e

