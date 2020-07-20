"""
@PRIMARY: cfg-020
@PRIMARY_DESC: The DLC APIs shall provide a method by which Multiple NIs can be added or removed dynamically on the same network
@SECONDARY: cfg-005, cfg-010, cfg-015,cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- configure more than one interface
- ensure that configuration is correct
- delete one interface
- ensure that configuration is correct
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
		if len(intfs) < 2:
			return lutfrc(LUTF_TEST_SKIP, "not enough interfaces for the test")
		t.api_config_ni('tcp', intfs)
		# verify config
		rc = t.get_nets(net='tcp', wrapper=True)
		if len(rc['local NI(s)']) != len(intfs):
			return lutfrc(LUTF_TEST_FAIL, "number of interfaces don't match", requested=intfs, configured=rc['local NI(s)'])
		for intf in rc['local NI(s)']:
			if not intf['interfaces'][0] in intfs:
				return lutfrc(LUTF_TEST_FAIL, "interfaces don't match", requested=intfs, configured=rc['local NI(s)'])
		# delete some random interface
		intf_idx = random.randint(0, len(intfs) - 1)
		intf_rm = [intfs[intf_idx]]
		del(intfs[intf_idx])
		t.api_del_ni('tcp', intf_rm)
		# verify config
		rc = t.get_nets(net='tcp', wrapper=True)
		if len(rc['local NI(s)']) != len(intfs):
			return lutfrc(LUTF_TEST_FAIL, "number of interfaces don't match", requested=intfs, configured=rc['local NI(s)'])
		for intf in rc['local NI(s)']:
			if not intf['interfaces'][0] in intfs:
				return lutfrc(LUTF_TEST_FAIL, "interfaces don't match", requested=intfs, configured=rc['local NI(s)'])
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

