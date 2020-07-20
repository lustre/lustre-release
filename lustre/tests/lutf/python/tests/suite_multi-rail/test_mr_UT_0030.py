"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-005, cfg-010, cfg-015,cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- unconfigure LNet
- unload LNet
- modify the /etc/modprobe.d/lustre.conf file to contain
	options libcfs cpu_npartitions=4 cpu_pattern="0[0] 1[1] 2[2] 3[3]"
- Look up the interfaces on the system
- configure intf1 on CPT 0, 2
- configure intf2 on CPT 1, 3
- configure intf3 on all CPTS.
- sanitize configuration
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
	found = False
	try:
		rc = t.get_nets(net=net, wrapper=True)
	except:
		return 'NOT_FOUND', None
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
		intfs = t.get_available_devs()
		if len(intfs) < 3:
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

		t.unconfigure_lnet()

		t.configure_lnet()
		intf0 = [intfs[0]]
		intf1 = [intfs[1]]
		intf2 = [intfs[2]]
		cpt1 = cpts[:int(len(cpts)/2)]
		cpt2 = cpts[int(len(cpts)/2):]

		t.api_config_ni('tcp1', intf0, global_cpts=cpt1)
		rc, cfg = verify_config(t, 'tcp1', intf0, cpt1)
		if rc != 'SUCCESS':
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=intf0, configured=cfg)
		t.api_config_ni('tcp1', intf1, global_cpts=cpt2)
		rc, cfg = verify_config(t, 'tcp1', intf1, cpt2)
		if rc != 'SUCCESS':
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=intf1, configured=cfg)
		t.api_config_ni('tcp1', intf2)
		rc, cfg = verify_config(t, 'tcp1', intf2, cpt1+cpt2)
		if rc != 'SUCCESS':
			return lutfrc(LUTF_TEST_FAIL, "Net configuration failed", requested=intf2, configured=cfg)

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e


