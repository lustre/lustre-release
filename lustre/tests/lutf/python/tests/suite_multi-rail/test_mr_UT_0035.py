"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- configure a NID using ip2nets
- sanitize
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
	try:
		devs = t.get_available_devs()
		intfs = t.get_available_intfs()
		if len(devs) < 1:
			return lutfrc(LUTF_TEST_SKIP, "not enough interfaces for the test")
		devip =  intfs['interfaces'][devs[0]]['ip']
		t.configure_lnet()
		ip2nets = 'tcp3(' + devs[0] + ')' + ' ' + devip
		t.api_config_ni('tcp3', ip2nets=ip2nets)
		rc, cfg = verify_config(t, 'tcp3', [devs[0]])
		if rc != 'SUCCESS':
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=tcp1intf, configured=cfg)
		return lutfrc(LUTF_TEST_PASS, cfg=cfg)
	except Exception as e:
		t.uninit()
		raise e

