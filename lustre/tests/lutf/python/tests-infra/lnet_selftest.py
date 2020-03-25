import os, yaml, random, pathlib, re
from lutf_basetest import BaseTest, lutfrc
from lutf_exception import LUTFError, LutfDumper
import selftest_template as st
from lutf_cmd import lutf_exec_local_cmd
from lutf import lutf_tmp_dir
from utility_paths import RMMOD, MODPROBE

class LNetSelfTest(BaseTest):
	def __init__(self, script=os.path.abspath(__file__), target=None, exception=True):
		super().__init__(script, target)
		self.__exception = exception

	def load(self):
		lutf_exec_local_cmd(MODPROBE + ' lnet_selftest')

	def unload(self):
		lutf_exec_local_cmd(RMMOD + ' lnet_selftest')

	def start(self, src, dst, size='1M', time=30, brw='write', concurrency=32, d1=1, d2=1):
		fail_res = {'nids': [], 'brwerr': 0, 'pingerr': 0, 'rpcerr': 0, 'drop': 0, 'exp': 0}
		fail_results = []
		rname = os.path.join(lutf_tmp_dir, "st"+str(random.getrandbits(32)) + '.report')
		script = os.path.join(lutf_tmp_dir, "st"+str(random.getrandbits(32)) + '.sh')
		with open(script, 'w') as f:
			numlines = f.write(''.join(st.selftest_script) % (size, time, brw, src, dst, concurrency, d1, d2, rname, '%5', rname))
		lutf_exec_local_cmd('/usr/bin/chmod u+rwx ' + script)
		try:
			rc = lutf_exec_local_cmd(script, expire=time+3)
		except Exception as e:
			if type(e) != StopIteration:
				raise e
			else:
				pass
		with open(rname, 'r') as f:
			input = f.readlines()
			res = re.search('(.+?): [Session (.+?) brw errors, (.+?) ping errors] [RPC: (.+?) errors, (.+?) dropped, (.+?) expired]', ''.join(input))
			if res:
				fail_res['nids'].append(res[1])
				fail_res['brwerr'] = int(res[2])
				fail_res['pingerr'] = int(res[3])
				fail_res['rpcerr'] = int(res[4])
				fail_res['drop'] = int(res[5])
				fail_res['exp'] = int(res[6])
				fail_results.append(fail_res)
		os.remove(rname)
		os.remove(script)
		if len(fail_results) > 0:
			if self.__exception:
				str_errors = yaml.dump(fail_results, Dumper=LutfDumper, indent=2, sort_keys=True)
				raise LUTFError("Errors in selftest: %s" % str_errors)
			return False, fail_results
		return True, None

	def stop(self):
		self.unload()
		return
