"""
@PRIMARY: s04
@PRIMARY_DESC: Illustrate how LUTFError, exceptions, can be propagated from the remote
to the master. And how they are stored in the results data base.
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: raise an LUTFError exception on the remote
"""

import os
from lutf import agents, me
from lutf_basetest import *
from lutf_exception import LUTFError
import logging

class SampleTestRException(BaseTest):
	def __init__(self, target=None):
		super().__init__(os.path.abspath(__file__),
				 target=target)

	def raiseAnException(self):
		LUTFError("raising Exception on %s" % (me.my_hostname()))

def run():
	la = agents.keys()
	if len(la) >= 1:
		logging.debug("Trying to execute on the agent")
		t = SampleTestRException(target=la[0])
		rc = t.raiseAnException()
	else:
		raise LUTFError("No agents available to run test")

	return lutfrc(LUTF_TEST_FAIL)

