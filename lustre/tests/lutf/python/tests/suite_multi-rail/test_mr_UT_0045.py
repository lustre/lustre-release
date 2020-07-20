"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- configure a NID using ip2nets
	tcp(eth0, eth1[1,3]) *.*.*.*
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

def verify_config(t, net, intfs, cpts):
	try:
		rc = t.get_nets(net=net, wrapper=True)
	except:
		return 'NOT_FOUND', None
	found = False
	for intf in rc['local NI(s)']:
		if intf['interfaces'][0] in intfs:
			found = True
			if yaml.load(intf['CPT'], Loader=yaml.FullLoader) != cpts:
				return 'FAILV', rc
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
		if len(devs) < 2:
			return lutfrc(LUTF_TEST_SKIP, "not enough interfaces for the test")
		num_partitions = me.get_cpuinfo()['NUMA node(s)']
		path = os.path.join(os.sep, 'etc', 'modprobe.d')
		f = LutfFile(path, full_path=True, target=la[0])
		count, line = f.get("cpu_npartitions=")
		if count >= 1:
			try:
				num_partitions = int(line[0].split('cpu_npartitions=')[1].split()[0])
			except:
				pass
		if num_partitions <= 1:
			return lutfrc(LUTF_TEST_SKIP, "not enough CPTs for this test. Require more than 1")

		cpts = list(range(0, num_partitions))
		cpt1 = cpts[:int(len(cpts)/2)]
		cpt2 = cpts[int(len(cpts)/2):]

		t.configure_lnet()
		ip2nets = 'tcp3(' + devs[0]+','+devs[1]+ str(cpt1) + ') *.*.*.*'
		print(ip2nets)
		t.api_config_ni('tcp3', ip2nets=ip2nets)
		rc, cfg = verify_config(t, 'tcp3', [devs[0]], cpt1+cpt2)
		if rc != 'SUCCESS':
			print('failed 1', ip2nets)
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=tcp1intf, configured=cfg)
		rc, cfg = verify_config(t, 'tcp3', [devs[1]], cpt1)
		if rc != 'SUCCESS':
			print('failed 2')
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=tcp1intf, configured=cfg)
		return lutfrc(LUTF_TEST_PASS, cfg=cfg)
	except Exception as e:
		t.uninit()
		raise e

