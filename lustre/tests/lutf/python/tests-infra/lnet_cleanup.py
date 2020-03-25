"""
1. Look through all the agents and determine the role each one has. IE: OSS, MDS
2. modprobe lnet
3. lnetctl lnet unconfigure
4. lustre_rmmod
"""

import os, yaml, logging
import lutf_agent
from lutf_basetest import BaseTest
from lnet_selftest import LNetSelfTest
import lnet
from utility_paths import lustre_rmmod

class LNetCleanup(BaseTest):
	def __init__(self, target=None):
		logging.critical("INSTANTIATING LNetCleanup for target " + str(target))
		super().__init__(os.path.abspath(__file__),
				 target=target)

	def unconfigure(self):
		logging.critical("LNetCleanup::unconfigure() --> lustre_rmmod()")
		lustre_rmmod()
#		st = LNetSelfTest()
#		try:
#			st.unload()
#		except:
#			pass
#		L = lnet.TheLNet()
#		L.unconfigure()

def clean_lnet():
	agents = lutf_agent.LutfAgents()
	agent_list = agents.keys()
	cleanups = []

	logging.critical("Cleaning LNet for " + str(agent_list))

	for a in agent_list:
		cleanups.append(LNetCleanup(target=a))

	for v in cleanups:
		v.unconfigure()


