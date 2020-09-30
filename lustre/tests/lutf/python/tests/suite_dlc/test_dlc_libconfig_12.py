"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. Call the lustre_lnet_config_ni() function to add a net.
2. use proper parameters
3. expect net to be configured properly
4. call the lustre_lnet_show_net() to verify the net was added proprely
5. call the lustre_lnet_del_net() to remove all networks added.
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
		t.configure_lnet()
		intfs = t.get_available_devs()
		t.api_config_ni('tcp', intfs)
		t.api_check_ni(net='tcp', num=len(intfs))
		t.api_del_ni('tcp', intfs)
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

