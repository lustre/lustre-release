"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE:  test yaml configuration
1. create a YAML file which configures networks and routes
2. Check configuration is correct
3. Delete the configuration
This test needs at least 2 nodes, one to be the router and one
where the routes are configured
"""

import os, yaml, random
import lnetconfig
from lutf import agents, me, lutf_tmp_dir
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lutf_file import LutfFile

def run():
	la = agents.keys()
	if len(la) < 2:
		msg = "need 2 agents to run test < 2 available"
		return lutfrc(LUTF_TEST_SKIP, msg=msg)

	t = LNetHelpers(target=la[0])
	t1 = LNetHelpers(target=la[1])
	try:
		t.configure_lnet()
		intfs = t.get_available_devs()
		t.api_config_ni('tcp', intfs)

		t1.configure_lnet()
		intfs = t1.get_available_devs()
		t1.api_config_ni('tcp', intfs)
		rtr_nids = t1.list_nids()
		if len(rtr_nids) <= 0:
			return lutfrc(LUTF_TEST_FAIL, msg="Failed to configure gateway")
		tmpFile = 'rtr'+str(random.getrandbits(32)) + '.yaml'
		tmpFile = os.path.join(lutf_tmp_dir, tmpFile)
		tmp = LutfFile(tmpFile, target=la[0])
		cfg =	'net:\n' + \
			'    - net type: tcp2\n' + \
			'      local NI(s):\n' + \
			'         - interfaces:\n' + \
			'              0: eth0\n' + \
			'           tunables:\n' + \
			'              peer_timeout: 180\n' + \
			'              peer_credits: 8\n' + \
			'              peer_buffer_credits: 0\n' + \
			'              credits: 256\n' + \
			'    - net type: tcp3\n' + \
			'      local NI(s):\n' + \
			'         - interfaces:\n' + \
			'              0: eth0\n' + \
			'           tunables:\n' + \
			'              peer_timeout: 140\n' + \
			'              peer_credits: 8\n' + \
			'              peer_buffer_credits: 0\n' + \
			'              credits: 1024\n' + \
			'    - net type: tcp4\n' + \
			'      local NI(s):\n' + \
			'         - interfaces:\n' + \
			'              0: eth0\n' + \
			'           tunables:\n' + \
			'              peer_timeout: 190\n' + \
			'              peer_credits: 16\n' + \
			'              peer_buffer_credits: 0\n' + \
			'              credits: 256\n' + \
			'route:\n'+ \
			'   - net: tcp5\n'+ \
			'     gateway: '+rtr_nids[0]+'\n'+ \
			'     hop: 4\n'+ \
			'     detail: 1\n'+ \
			'     seq_no: 1\n'+ \
			'   - net: tcp6\n'+ \
			'     gateway: '+rtr_nids[0]+'\n'+ \
			'     hop: 9\n'+ \
			'     detail: 1\n'+ \
			'     seq_no: 2\n'+ \
			'   - net: tcp7\n'+ \
			'     gateway: '+rtr_nids[0]+'\n'+ \
			'     hop: 6\n'+ \
			'     detail: 1\n'+ \
			'     seq_no: 3\n'
		tmp.open('w')
		tmp.write(cfg)
		tmp.close()

		t.api_yaml_cfg(tmp.get_full_path(), 8, del_count=2)
		tmp.remove()
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		t1.uninit()
		raise e

