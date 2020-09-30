"""
@PRIMARY: s03
@PRIMARY_DESC: Illustrate remote execution of class methods
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: Collect the interfaces of an available remote node and perform a sum.
Return the interfaces and the sum to be stored on the master
"""

import yaml, logging, os
from lutf import agents, me
from lutf_basetest import *
from lutf_exception import LUTFError

class SampleTest(BaseTest):
	def __init__(self, target=None):
		super().__init__(os.path.abspath(__file__),
				 target=target)

	def get_intfs_and_add(self, a, b):
		myintf = me.list_intfs()
		sum = a + b
		return sum, myintf

def run():
	la = agents.keys()
	if len(la) >= 1:
		logging.debug("Trying to execute on the agent")
		t = SampleTest(target=la[0])
		sum, intfs = t.get_intfs_and_add(3,6)
		print(yaml.dump(intfs, sort_keys=False))
	else:
		raise LUTFError("No agents available to run test")

	return lutfrc(LUTF_TEST_PASS, intfs=yaml.dump(intfs, sort_keys=False), sum=sum)


