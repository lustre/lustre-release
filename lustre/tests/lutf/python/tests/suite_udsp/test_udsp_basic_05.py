"""
@PRIMARY: N/A
@PRIMARY_DESC: Verify that UDSP rule designating src-dst nid pair can be added
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE:
- configure LNet
- add udsp rule designating a source-destination nid pair
- verify that the rule has been added
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


test_action_list = [{'udsp_cmd': "add --src 192.168.122.1@tcp1 --dst 192.168.122.101@tcp1",
                     'show_res': {'udsp': [{'idx': 0, 'src': '192.168.122.1@tcp1', 'dst': '192.168.122.101@tcp1', 'rte': 'NA'}]}}]

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
		rc = t.exec_udsp_cmd(test_action_list[0]['udsp_cmd'])
		rc = t.check_udsp_expected(test_action_list[0]['show_res'])
		if not rc:
			return lutfrc(LUTF_TEST_FAIL)
		rc = t.cleanup_udsp()
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e


