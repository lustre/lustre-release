"""
@PRIMARY: LU-10360-01
@PRIMARY_DESC: Eanble/Disable dynamic NIDs via dynamic_nids parameter
@SECONDARY: LU-10360-02
@DESIGN: Standard Lustre sysfs module parameters setting
@TESTCASE:
On the client and on the MDS
	lctl set_param mgc.*.dynamic_nids=1
		lctl get_param mgc.*.dynamic_nids
			Check the value is 1
On the client and on the MDS
	lctl set_param mgc.*.dynamic_nids=0
		lctl get_param mgc.*.dynamic_nids
			Check the value is 0
"""

import os, re, yaml, logging
from time import sleep
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import *
from lnet_selftest import LNetSelfTest
from lnet_helpers import LNetHelpers
from lustre_node import SimpleLustreNode
from lustre_roles import *
from lustre_fs import SimpleLustreFS
import lutf_common_def as common

def set_check_dynamic_nids(node, prev, new):
	dn = node.get_dynamic_nids()
	if dn != prev:
		return False, prev
	node.set_dynamic_nids(new)
	dn = node.get_dynamic_nids()
	if dn != new:
		return False, new
	return True, new

def run():
	la = agents.keys()
	if len(la) < 3:
		return lutfrc(LUTF_TEST_SKIP,
		    msg="Not enough agents to setup a lustre FS. 3 needed %d found" % len(la))
	try:
		lustrefs = SimpleLustreFS(la)
		MGSs = lustrefs.get_mgs_nodes()
		OSSs = lustrefs.get_oss_nodes()
		clients = lustrefs.get_client_nodes()
		if len(MGSs) < 1 or len(OSSs) < 1 or len(clients) < 1:
			return lutfrc(LUTF_TEST_SKIP, "Unexpected cluster: MGSs %d, OSSs %d, clients %d" % (len(MGSs), len(OSSs), len(clients)))
		lustrefs.configure_nets()
		lustrefs.mount_servers(num_mgs=1, num_oss=1)
		lustrefs.mount_clients(num=1)
		rc, value = set_check_dynamic_nids(MGSs[0], 0, 1)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "expected dynamic_nids to be set to: " + str(value))
		rc, value = set_check_dynamic_nids(MGSs[0], 1, 0)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "expected dynamic_nids to be set to: " + str(value))
		rc, value = set_check_dynamic_nids(clients[0], 0, 1)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "expected dynamic_nids to be set to: " + str(value))
		rc, value = set_check_dynamic_nids(clients[0], 1, 0)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "expected dynamic_nids to be set to: " + str(value))
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		raise e

