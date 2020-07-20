"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- add tcp1 network with all interfaces on the system.
- add peer 1 with 2 NIs to tcp1 using the API
- set NUMA range to 100
- check config
- delete config using YAML
- reconfigure using YAML
- check config
"""

import os
import yaml, random, threading, time
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lutf_file import LutfFile
from lnet_selftest import LNetSelfTest

def run():
	la = agents.keys()
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	t1 = LNetHelpers(target=la[0])
	try:
		t1.configure_lnet()
		t1.configure_net('tcp1')
		t1.set_discovery(0)
		t1.api_config_peer(prim_nid='192.168.122.34@tcp', nids='192.168.122.[35-36]@tcp')
		t1.set_numa_range(100)
		cfg = t1.get_config()
		t1.uninit()
		t1.unconfigure_lnet()
		t1.configure_lnet()
		t1.configure_yaml(cfg)
		cfg2 = t1.get_config()
		if cfg != cfg2:
			return lutfrc(LUTF_TEST_FAIL, "YAML config failed", required=cfg, implemented=cfg2)
		return lutfrc(LUTF_TEST_PASS, required=cfg, implemented=cfg2)
	except Exception as e:
		t1.uninit()
		raise e

