"""
@PRIMARY: cfg-060
@PRIMARY_DESC: lnetctl utility shall provide a command line front end interface to configure local NIs by calling the DLC APIs
@SECONDARY: cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- set NUMA range to -1
- check config fails
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
		t.configure_net('tcp')
		try:
			t.set_numa_range(-1)
		except:
			return lutfrc(LUTF_TEST_PASS)
		return lutfrc(LUTF_TEST_FAIL, "Numa range set to -1", cfg=t.get_globals())
	except Exception as e:
		t.uninit()
		raise e

