"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. turn on LNet discovery
2. run lnetctl discover
3. ensure that peers are discovered
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
	if len(la) < 2:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	helpers = []
	try:
		for i in range(0, len(la)):
			t = LNetHelpers(target=la[i])
			intfs = t.get_available_devs()
			t.configure_lnet()
			t.configure_net('tcp', intfs)
			t.set_discovery(1)
			helpers.append(t)

		main = helpers[0]
		for i in range(1, len(helpers)):
			actual_nids = helpers[i].list_nids()
			discovered_nids = main.discover(actual_nids[0])
			if len(actual_nids) != len(discovered_nids):
				return lutfrc(LUTF_TEST_FAIL, "discovered NIDs are not correct",
					      discovered_nids=discovered_nids, actual_nids=actual_nids)
			for nid in discovered_nids:
				if nid not in actual_nids:
					return lutfrc(LUTF_TEST_FAIL, "discovered NID is unknown",
						      discovered_nids=discovered_nids, actual_nids=actual_nids)

		for h in helpers:
			h.unconfigure_lnet()

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		for h in helpers:
			h.uninit()
		raise e

