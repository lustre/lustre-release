"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. Call the lustre_lnet_config_route() function to insert route.
2. Delete that route but specify no gw
3. Expect an error
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
		logging.debug('node is %s. rtr is %s' % (la[0], la[1]))
		t = LNetHelpers(script=os.path.abspath(__file__), target=la[0])
		rtr = LNetHelpers(script=os.path.abspath(__file__), target=la[1])
		t.configure_net('tcp')
		rtr.configure_net('tcp')
		rtr_nids = rtr.list_nids()
		logging.debug('rtr nids are: %s' % str(rtr_nids))
		if len(rtr_nids) < 1:
			return lutfrc(LUTF_TEST_FAIL, "No NIDS available for rtr")
		t.api_configure_route('tcp3', rtr_nids[0], 4)
		t.set_exception(False)
		rc, info = t.api_del_route(rnet='tcp4', gw='10.10.10.10@tcp')
		if rc:
			# expect failure
			return lutfrc(LUTF_TEST_FAIL, details=info)
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		rtr.uninit()
		raise e

