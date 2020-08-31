"""
@PRIMARY: N/A
@PRIMARY_DESC: Verify that using incorrect idx parameter value with UDSP lnetctl resuts in an error
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE:
- configure LNet
- add udsp rule prioritizing local network
- attempt to delete the rule providing incorrect idx parameter
- verify that the rule is not deleted
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


test_action_list = [{'udsp_cmd': "add --src tcp1",
                     'show_res': {'udsp': [{'idx': 0, 'src': 'tcp1', 'dst': 'NA', 'rte': 'NA', 'action': {'priority': 0}}]}},
		    {'udsp_cmd': "del --idx=20",
                     'show_res': {'udsp': [{'idx': 0, 'src': 'tcp1', 'dst': 'NA', 'rte': 'NA', 'action': {'priority': 0}}]}},
		    {'udsp_cmd': "del --idx=-1",
                     'show_res': {'udsp': [{'idx': 0, 'src': 'tcp1', 'dst': 'NA', 'rte': 'NA', 'action': {'priority': 0}}]}},
		    {'udsp_cmd': "del --idx=abcd",
                     'show_res': {'udsp': [{'idx': 0, 'src': 'tcp1', 'dst': 'NA', 'rte': 'NA', 'action': {'priority': 0}}]}}]

def run():
	la = agents.keys()
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "No agents to run test")
	try:
		t = LNetHelpers(target=la[0])
		t.configure_lnet()
		if not t.check_udsp_present():
			return lutfrc(LUTF_TEST_SKIP, "UDSP feature is missing")
		rc = t.check_udsp_empty()
		if not rc:
                        return lutfrc(LUTF_TEST_FAIL)
		count = 0
		for test_action in test_action_list:
			count+=1
			print("Test action: ", count)
			rc = t.exec_udsp_cmd(test_action['udsp_cmd'])
			rc = t.check_udsp_expected(test_action['show_res'])
			if not rc:
				return lutfrc(LUTF_TEST_FAIL)
		rc = t.cleanup_udsp()
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e


