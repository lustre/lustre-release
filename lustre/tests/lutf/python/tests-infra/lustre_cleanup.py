"""
1. Look through all the agents and determine the role each one has. IE: OSS, MDS
2. Umount clients
3. Umount OSS
4. Umount MDS
"""

import os
import yaml, logging
import lutf_agent
from lutf_basetest import BaseTest
from lutf_cmd import lutf_exec_local_cmd
from lustre_roles import *
from utility_paths import MOUNT, UMOUNT

class LustreCleanup(BaseTest):
	def __init__(self, target=None):
		logging.critical("INSTANTIATING LustreCleanup for target " + str(target))
		super().__init__(os.path.abspath(__file__),
				 target=target)

	def __get_lustre_mount(self):
		mounts = []
		rc = lutf_exec_local_cmd(MOUNT)
		if not rc:
			return mounts
		out = rc[0].decode('utf-8')
		if len(out) == 0:
			return mounts
		tmp = out.split("\n")
		for e in tmp:
			if 'type lustre' in e:
				mounts.append(e.strip())
		return mounts

	def get_role(self):
		node_info = {}
		mounts = self.__get_lustre_mount()

		if len(mounts) == 0:
			return LUSTRE_NODE_ROLE_UNDEFINED
		for m in mounts:
			if 'svname' in m:
				# this is a server of some form so let's try and
				# figure out what it is
				if os.path.isfile('/sys/fs/lustre/mgs/MGS/uuid'):
					if LUSTRE_NODE_ROLE_MGS in node_info:
						node_info[LUSTRE_NODE_ROLE_MGS].append(m.split()[2])
					else:
						node_info[LUSTRE_NODE_ROLE_MGS] = [m.split()[2]]
				elif os.path.isfile('/sys/fs/lustre/mds/MDS/uuid'):
					if LUSTRE_NODE_ROLE_MDS in node_info:
						node_info[LUSTRE_NODE_ROLE_MDS].append(m.split()[2])
					else:
						node_info[LUSTRE_NODE_ROLE_MDS] = [m.split()[2]]
				elif os.path.isfile('/sys/fs/lustre/ost/OSS/uuid'):
					if LUSTRE_NODE_ROLE_OSS in node_info:
						node_info[LUSTRE_NODE_ROLE_OSS].append(m.split()[2])
					else:
						node_info[LUSTRE_NODE_ROLE_OSS] = [m.split()[2]]
				elif os.path.isdir('/sys/fs/lustre/mdt/'):
					for subdir, dirs, files in os.walk('/sys/fs/lustre/mdt/'):
						for f in files:
							if f == 'uuid':
								if LUSTRE_NODE_ROLE_MDT in node_info:
									node_info[LUSTRE_NODE_ROLE_MDT].append(m.split()[2])
								else:
									node_info[LUSTRE_NODE_ROLE_MDT] = [m.split()[2]]
			else:
				if LUSTRE_NODE_ROLE_CLIENT in node_info:
					node_info[LUSTRE_NODE_ROLE_CLIENT].append(m.split()[2])
				else:
					node_info[LUSTRE_NODE_ROLE_CLIENT] = [m.split()[2]]

		return node_info

	def umount(self, point):
		lutf_exec_local_cmd(UMOUNT+" "+point)

def clean_lustre():
	agents = lutf_agent.LutfAgents()
	agent_list = agents.keys()
	cleanups = []
	logging.critical("Cleaning up lustre for " + str(agent_list))
	for a in agent_list:
		cleanups.append({'obj': LustreCleanup(target=a), 'role': ''})

	for v in cleanups:
		v['role'] = v['obj'].get_role()

	for v in cleanups:
		if LUSTRE_NODE_ROLE_CLIENT in v['role']:
			for mp in v['role'][LUSTRE_NODE_ROLE_CLIENT]:
				v['obj'].umount(mp)
	for v in cleanups:
		if LUSTRE_NODE_ROLE_OSS in v['role']:
			for mp in v['role'][LUSTRE_NODE_ROLE_OSS]:
				v['obj'].umount(mp)
	for v in cleanups:
		if LUSTRE_NODE_ROLE_MDT in v['role']:
			for mp in v['role'][LUSTRE_NODE_ROLE_MDT]:
				v['obj'].umount(mp)
	for v in cleanups:
		if LUSTRE_NODE_ROLE_MDS in v['role']:
			for mp in v['role'][LUSTRE_NODE_ROLE_MDS]:
				v['obj'].umount(mp)
	for v in cleanups:
		if LUSTRE_NODE_ROLE_MGS in v['role']:
			for mp in v['role'][LUSTRE_NODE_ROLE_MGS]:
				v['obj'].umount(mp)

