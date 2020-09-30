"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: 1. Create a YAML file of multiple routes
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
		tmp = LutfFile(tmpFile, full_path=True, target=la[0])
		cfg =	'route:\n'+ \
			'   - net: tcp4\n'+ \
			'     gateway: '+rtr_nids[0]+'\n'+ \
			'     hop: 4\n'+ \
			'     detail: 1\n'+ \
			'     seq_no: 1\n'+ \
			'   - net: tcp5\n'+ \
			'     gateway: '+rtr_nids[0]+'\n'+ \
			'     hop: 9\n'+ \
			'     detail: 1\n'+ \
			'     seq_no: 2\n'+ \
			'   - net: tcp6\n'+ \
			'     gateway: '+rtr_nids[0]+'\n'+ \
			'     hop: 6\n'+ \
			'     detail: 1\n'+ \
			'     seq_no: 3\n'
		tmp.open('w')
		tmp.write(cfg)
		tmp.close()

		t.api_yaml_cfg(tmp.get_full_path(), 3)
		tmp.remove()
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		t1.uninit()
		raise e
