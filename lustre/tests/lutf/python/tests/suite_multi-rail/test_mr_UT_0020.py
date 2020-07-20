"""
@PRIMARY: cfg-020
@PRIMARY_DESC: The DLC APIs shall provide a method by which Multiple NIs can be added or removed dynamically on the same network
@SECONDARY: cfg-005, cfg-010, cfg-015,cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- split the list of interfaces into two lists
- Configure 1 list on tcp1 and the 2nd list on tcp2
- verify configuration
- delete all NIs from 1st list
- verify configuration. There should be no more tcp1
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

def verify_config(t, net, intfs):
	try:
		rc = t.get_nets(net=net, wrapper=True)
	except:
		return 'NOT_FOUND', None
	if len(rc['local NI(s)']) != len(intfs):
		return 'FAILV', rc
	for intf in rc['local NI(s)']:
		if not intf['interfaces'][0] in intfs:
			return 'FAILV', rc
	return 'SUCCESS', rc

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
		tcp1intf = intfs[:int(len(intfs)/2)]
		tcp2intf = intfs[int(len(intfs)/2):]

		t.api_config_ni('tcp1', tcp1intf)
		rc, cfg = verify_config(t, 'tcp1', tcp1intf)
		if rc != 'SUCCESS':
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=tcp1intf, configured=cfg)

		t.api_config_ni('tcp2', tcp2intf)
		rc, cfg = verify_config(t, 'tcp2', tcp2intf)
		if rc != 'SUCCESS':
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=tcp1intf, configured=cfg)
		# delete some random interface
		t.api_del_ni('tcp1', tcp1intf)
		# verify config
		rc, cfg = verify_config(t, 'tcp1', tcp1intf)
		if rc != 'NOT_FOUND':
			return lutfrc(LUTF_TEST_FAIL, "Failed to remove interfaces", remove=tcp1intf, configured=cfg)
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

