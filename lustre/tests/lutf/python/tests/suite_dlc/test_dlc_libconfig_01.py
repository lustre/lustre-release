"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: Test missing mandatory route parameter behavior
"""

import os
import yaml
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError

class TestMissingParam(BaseTest):
	def __init__(self, target=None):
		super().__init__(os.path.abspath(__file__),
				 target=target)

	def missing_net_param(self):
		L = TheLNet()
		success = False
		rc, yaml_err = lnetconfig.lustre_lnet_config_route(None, '10.211.55.1@tcp1', -1, -1, -1, -1)
		if (rc == lnetconfig.LUSTRE_CFG_RC_MISSING_PARAM):
			success = True
		else:
			success = False
		return success

	def missing_gw_param(self):
		L = TheLNet()
		success = False
		rc, yaml_err = lnetconfig.lustre_lnet_config_route('tcp', None, -1, -1, -1, -1)
		if (rc == lnetconfig.LUSTRE_CFG_RC_MISSING_PARAM):
			success = True
		else:
			success = False
		return success

	def missing_gw_net_param(self):
		L = TheLNet()
		success = False
		rc, yaml_err = lnetconfig.lustre_lnet_config_route(None, None, -1, -1, -1, -1)
		if (rc == lnetconfig.LUSTRE_CFG_RC_MISSING_PARAM):
			success = True
		else:
			success = False
		return success

def run():
	la = agents.keys()
	if len(la) >= 1:
		t = TestMissingParam(target=la[0])
		rc1 = t.missing_net_param()
		rc2 = t.missing_gw_param()
		rc3 = t.missing_gw_net_param()
		if not rc1 or not rc2 or not rc3:
			return lutfrc(-1, missing_net_param=rc1,
				      missing_gw_param=rc2,
				      missing_gw_net_param=rc3)
		return lutfrc(LUTF_TEST_PASS)
	else:
		return lutfrc(LUTF_TEST_SKIP, "No agents to run test")

