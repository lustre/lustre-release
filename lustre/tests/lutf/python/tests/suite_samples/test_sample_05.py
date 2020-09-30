"""
@PRIMARY: s07
@PRIMARY_DESC: Illustrate how an instance of a class can be propagated from the remote
to the master.
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: Instantiate a class on the remote and return it to the master
"""
import os
from lutf import agents
from lutf_basetest import *
from lutf_exception import LUTFError
import logging

class SampleRCclass():
	def __init__(self, num):
		self.num = num

class SampleTest(BaseTest):
	def __init__(self, target=None):
		super().__init__(os.path.abspath(__file__),
				 target=target)

	def instantiate(self):
		obj = SampleRCclass(2020)
		return obj

def run():
	la = agents.keys()
	if len(la) >= 1:
		logging.debug("Trying to execute on the agent")
		t = SampleTest(target=la[0])
		obj = t.instantiate()
	else:
		raise LUTFError("No agents available to run test")

	return lutfrc(LUTF_TEST_PASS, num=obj.num)

