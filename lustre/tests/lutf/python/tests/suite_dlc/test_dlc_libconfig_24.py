"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: test malconfigured yaml
"""


import os
import yaml
from lutf import agents, me
from lutf_basetest import BaseTest
import lnet

class SampleTest(BaseTest):
	def __init__(self, target=None):
		super().__init__(os.path.abspath(__file__),
				 target=target)

	def simple_lnet_configure(self):
		L = lnet.TheLNet()
		L.nets['tcp'] = [{'interfaces': 'eth0', 'peer_credits': 128},
				 {'interfaces': 'eth1', 'peer_credits': 128}]
		L.configure()
		L1 = lnet.TheLNet()
		L1.update()
		if not L1.nets == L.nets:
			return False
		return True

def run():
	test = SampleTest()
	rc = test.simple_lnet_configure()
	return test.format(step1=rc)


