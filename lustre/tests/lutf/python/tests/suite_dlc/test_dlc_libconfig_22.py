"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: Test a simple routing setup
"""

import os, logging
import yaml
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import *
from lnet_selftest import LNetSelfTest
from lnet_helpers import LNetHelpers

class TestTraffic:
	def __init__(self, target=None):
		self.st = LNetSelfTest(os.path.abspath(__file__), target=target)
		self.lh = LNetHelpers(os.path.abspath(__file__), target=target)

def run():
	la = agents.keys()
	if len(la) < 3:
		return lutfrc(LUTF_TEST_SKIP, msg="Not enough agents to run routing test. 3 needed %d found" % len(la))

	# setup peer A for lnet_self test
	# setup peer B for lnet_self test
	# setup router
	# run lnet_selftest
	#
	peer1 = TestTraffic(target=la[0])
	peer2 = TestTraffic(target=la[1])
	rtr = TestTraffic(target=la[2])
	try:
		peer1.lh.configure_net('tcp')
		peer2.lh.configure_net('tcp2')
		peer1.st.load()
		peer2.st.load()
		rtr.lh.configure_net('tcp')
		rtr.lh.configure_net('tcp2')
		rtr.lh.api_set_routing(True)
		rtr_nids = rtr.lh.list_nids()
		p = '(.+?)@tcp$'
		p1 = '(.+?)@tcp2$'
		tcp_nids = [nid for nid in rtr_nids if re.match(p, nid)]
		tcp2_nids = [nid for nid in rtr_nids if re.match(p1, nid)]
		# setup the routing
		peer1.lh.api_configure_route('tcp2', tcp_nids[0])
		peer2.lh.api_configure_route('tcp', tcp2_nids[0])
		peer1_nid = peer1.lh.list_nids()[0]
		peer2_nid = peer2.lh.list_nids()[0]
		peer1.st.start(peer1_nid, peer2_nid)
		peer1.st.unload()
		peer2.st.unload()
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		peer1.st.unload()
		peer2.st.unload()
		peer1.lh.uninit()
		peer2.lh.uninit()
		rtr.lh.uninit()
		raise e

