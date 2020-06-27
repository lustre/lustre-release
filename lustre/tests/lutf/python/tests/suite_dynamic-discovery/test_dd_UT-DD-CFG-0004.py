"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. Turn off discovery via YAML
2. Grab global configuration and check discovery is off
3. Turn on discovery via YAML
4. Grab global configuration and check discovery is on
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

def discovery_set_check(target, helper, value):
	tmpFile = 'rtr'+str(random.getrandbits(32)) + '.yaml'
	tmpFile = os.path.join(lutf_tmp_dir, tmpFile)
	tmp = LutfFile(tmpFile, target=target)
	cfg =	'global:\n'+ \
		'   discovery: %d\n' % value
	tmp.open('w')
	tmp.write(cfg)
	tmp.close()
	helper.api_yaml_cfg(tmp.get_full_path(), 1, delete=False)
	tmp.remove()
	cfg = helper.get_globals()
	return cfg['global']['discovery'] == value, cfg

def run():
	la = agents.keys()
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	t = LNetHelpers(target=la[0])
	try:
		t.configure_lnet()
		intfs = t.get_available_devs()
		t.configure_net('tcp', intfs)
		rc, cfg = discovery_set_check(la[0], t, 0)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "Discovery wasn't turned off",
					global_cfg=cfg)

		rc, cfg = discovery_set_check(la[0], t, 1)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "Discovery wasn't turned on",
					global_cfg=cfg)

		t.unconfigure_lnet()

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e
