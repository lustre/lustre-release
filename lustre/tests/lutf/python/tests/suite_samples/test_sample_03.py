"""
@PRIMARY: s04
@PRIMARY_DESC: Illustrate the LNet wrapper class and how it can be used to configure networks
and compare the requested configuration with the actual configuration
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: Setup an LNet instance, L, with a tcp network and 2 interfaces eth0 and eth1
Setup a second LNet instance, L1, to be updated with what has actually been configured
Compare both instances. If they are the same then the test succeeded. Otherwise Failed
"""

import os
import yaml
from lutf import agents, me
from lutf_basetest import *
import lnet

class SampleTest(BaseTest):
	def __init__(self, target=None):
		super().__init__(os.path.abspath(__file__),
				 target=target)

	def simple_lnet_configure(self):
		L = lnet.TheLNet()
		L.nets['tcp'] = [{'interfaces': 'eth0', 'peer_credits': 128, 'peer_timeout': 180, 'peer_buffer_credits': 0, 'credits': 256},
				 {'interfaces': 'eth1', 'peer_credits': 128, 'peer_timeout': 180, 'peer_buffer_credits': 0, 'credits': 256}]
		L.configure()
		L1 = lnet.TheLNet()
		L1.update()
		if not L1.nets == L.nets:
			return False
		return True

def run():
	test = SampleTest()
	rc = test.simple_lnet_configure()
	return lutfrc(LUTF_TEST_PASS, step1=rc)


