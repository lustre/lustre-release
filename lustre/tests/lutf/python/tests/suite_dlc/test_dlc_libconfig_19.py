"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. Create a YAML file of multiple networks
2. Call the lustre_yaml_config() - to configure
3. Call the lustre_yaml_show() - to show and verify what has been configured
4. Call the lustre_yaml_del() - to delete what has been configured.
5. Call the lustre_yaml_show() -  to show and verify routes are no longer configured
"""

import os
import yaml, random
import lnetconfig
from lutf import agents, me, lutf_tmp_dir
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lutf_file import LutfFile

def run():
	la = agents.keys()
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, msg="No agents to run test")

	t = LNetHelpers(target=la[0])
	try:
		t.configure_lnet()
		intfs = t.get_available_devs()
		t.api_config_ni('tcp', intfs)

		tmpFile = 'net'+str(random.getrandbits(32)) + '.yaml'
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
			'              credits: 256\n'
		tmp.open('w')
		tmp.write(cfg)
		tmp.close()

		# configure lo (default), tcp, tcp2, tcp3, tcp4
		t.api_yaml_cfg(tmp.get_full_path(), 5)
		tmp.remove()
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

