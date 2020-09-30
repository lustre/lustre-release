"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: enable disable routes
Enable routing with the specified tiny, small and large buffers.
Check it was enabled properly
Disalbe routing
Check it was disabled properly
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
	if len(la) < 1:
		return lutfrc(LUTF_TEST_SKIP, "No agents to run test")
	t = LNetHelpers(target=la[0])
	try:
		t.configure_lnet()
		intfs = t.get_available_devs()
		t.api_config_ni('tcp', intfs)

		tmpFile = 'rtr'+str(random.getrandbits(32)) + '.yaml'
		tmpFile = os.path.join(lutf_tmp_dir, tmpFile)
		tmp = LutfFile(tmpFile, target=la[0])
		cfg =	'routing:\n' + \
			'   - seq_no: 1\n' + \
			'     enable: 1\n' + \
			'buffers:\n' + \
			'   - seq_no: 2\n' + \
			'     tiny: 1024\n' + \
			'     small: 8192\n' + \
			'     large: 512\n'

		tmp.open('w')
		tmp.write(cfg)
		tmp.close()
		cptfn = os.path.join(os.path.sep, 'sys', 'kernel', 'debug', 'lnet', 'cpu_partition_table')
		cptf = LutfFile(cptfn, full_path=True, target=la[0])
		cptf.open('r')
		data = cptf.readlines()
		cptf.close()
		t.api_yaml_cfg(tmp.get_full_path(), len(data)+4, delete=False)
		tmp.remove()

		tmpFile = 'rtr'+str(random.getrandbits(32)) + '.yaml'
		tmpFile = os.path.join(lutf_tmp_dir, tmpFile)
		tmp = LutfFile(tmpFile, target=la[0])
		cfg =	'routing:\n' + \
			'   - seq_no: 1\n' + \
			'     enable: 1\n'
		tmp.open('w')
		tmp.write(cfg)
		tmp.close()
		# find out the number of CPTs
		t.api_yaml_cfg(tmp.get_full_path(), len(data)+4, delete=False)
		tmp.remove()

		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t.uninit()
		raise e

