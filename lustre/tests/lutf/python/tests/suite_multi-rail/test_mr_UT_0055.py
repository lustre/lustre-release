"""
@PRIMARY: cfg-060
@PRIMARY_DESC: lnetctl utility shall provide a command line front end interface to configure local NIs by calling the DLC APIs
@SECONDARY: cfg-065
@DESIGN: N/A
@TESTCASE:
- Configure net using lnetctl (This is done via the LNet class)
- verify configuration
- Delete an interface
- verify configuration
- set numa range
- verify configuration
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
	found = False
	for intf in rc['local NI(s)']:
		if intf['interfaces'][0] in intfs:
			found = True
	if not found:
		return 'FAILV', rc
	return 'SUCCESS', rc

def run():
	la = agents.keys()
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	t = LNetHelpers(target=la[0])
	l = TheLNet(target=la[0])
	try:
		devs = t.get_available_devs()
		if len(devs) < 1:
			return lutfrc(LUTF_TEST_SKIP, "not enough interfaces for the test")
		t.configure_lnet()
		l.add_ni('tcp', devs[0])
		rc, cfg = verify_config(t, 'tcp', [devs[0]])
		if rc != 'SUCCESS':
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=tcp1intf, configured=cfg)
		l.del_ni('tcp', devs[0])
		# This is expected to fail
		rc, cfg = verify_config(t, 'tcp', [devs[0]])
		if rc == 'SUCCESS':
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=tcp1intf, configured=cfg)
		t.set_numa_range(900)
		rc = t.get_globals()
		if rc['global']['numa_range'] != 900:
			return lutfrc(LUTF_TEST_FAIL, "Failed to set numa range", requested=900, configured=rc['global']['numa_range'])
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

