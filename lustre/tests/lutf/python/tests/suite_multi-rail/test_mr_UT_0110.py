"""
@PRIMARY: cfg-020
@PRIMARY_DESC: The DLC APIs shall provide a method by which Multiple NIs can be added or removed dynamically on the same network
@SECONDARY: cfg-005, cfg-010, cfg-015,cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- Look up the interfaces on the system
- configure all interfaces under the same net
- attempt to delete a non existing NI
"""

import os
import yaml, random
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lutf_file import LutfFile

def run():
	la = agents.keys()
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	t = LNetHelpers(target=la[0])
	try:
		t.configure_lnet()
		intfs = t.get_available_devs()
		# configure/unconfigure_net does un/configuration and verification
		t.api_config_ni('tcp', intfs)
		try:
			t.api_del_ni('tcp', ['amir'])
		except:
			t.uninit()
			return lutfrc(LUTF_TEST_PASS)
		return lutfrc(LUTF_TEST_FAIL, "deleting an unknown ni succeeded")
	except Exception as e:
		t.uninit()
		raise e

