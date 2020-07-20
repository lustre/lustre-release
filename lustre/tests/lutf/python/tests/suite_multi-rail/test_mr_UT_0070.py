"""
@PRIMARY: cfg-020
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-005, cfg-010, cfg-015,cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- Configure all interfaces on tcp0 network
- Configure two of interfaces on tcp1 network
- dump the YAML output
- sanitize the YAML output to make sure that networks were configured properly
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
		intfs = t.get_available_devs()
		if len(intfs) < 3:
			return lutfrc(LUTF_TEST_SKIP, "not enough interfaces for the test")
		t.configure_lnet()
		tcp1intfs = [intfs[0], intfs[1]]
		tcp2intfs = [intfs[1], intfs[2]]

		t.api_config_ni('tcp1', tcp1intfs)
		rc, cfg = verify_config(t, 'tcp1', tcp1intfs)
		if rc != 'SUCCESS':
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=intf0, configured=cfg)
		t.api_config_ni('tcp2', tcp2intfs)
		rc, cfg = verify_config(t, 'tcp2', tcp2intfs)
		if rc != 'SUCCESS':
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=intf1, configured=cfg)

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

