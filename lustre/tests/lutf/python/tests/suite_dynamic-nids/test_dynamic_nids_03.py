"""
@PRIMARY: LU-10360-05
@PRIMARY_DESC: All MGCs must have dynamic_nids set in order for the feature to work.
@TESTCASE:
    Setup a file system consistent of:
        1 node: MGS/MDS
        1 node: OSS should have 2 IP addresses
        1 node: Client
    Mount the File System and the client
        Use only one of the IP addresses on the OSS
    Disable the dynamic_nids feature on both the MDS and the client
    Write multiple files to the FS
    Read back the files and make sure they are correct
    unmount the OSS and remove lustre modules
    Change the OSS configuration to use the other IP address for NID
    load lustre on the OSS and re mount
    LS the file system.
        the metadata might be cached on the client and the LS could work
    Writing to the FS should timeout and fail.
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
from lutf_utils import *

def write_verify_to_fs(lustrefs):
	data = generate_random_bytes(1048576)
	files = []
	# write 3 files
	for i in range(0, 3):
		files.append(lustrefs.write(0, data, thread=True))
	# read and verify each of the files written
	for f in files:
		if not lustrefs.read_verify(0, data, f, thread=True):
			return False, f
	return True, None

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

		# configure the OSS to use the first IP address
		oss = lustrefs.get_oss_nodes()
		oss_intfs = oss[0].list_intfs()
		if len(oss_intfs) <= 1:
			return lutfrc(LUTF_TEST_SKIP, "not enough interfaces on oss %s (%s)" % (oss[0].get_node_name(), oss[0].get_node_hostname()))
		oss_net = {'tcp': [oss_intfs[0]]}
		lustrefs.configure_nets(oss=oss_net)
		lustrefs.mount_servers(num_mgs=1, num_oss=1)
		lustrefs.mount_clients(num=1)
		rc, f = write_verify_to_fs(lustrefs)
		if not rc:
			lutfrc(LUTF_TEST_FAIL, "Failed to verify data on " + f)
		oss[0].unconfigure_lustre()
		oss_net = {'tcp': [oss_intfs[1]]}
		oss[0].configure_net(oss_net)
		oss[0].commit()
		oss[0].configure_lustre(lustrefs.get_mgs_nids())
		sleep(10)
		try:
			rc, f = write_verify_to_fs(lustrefs)
			if rc:
				lutfrc(LUTF_TEST_FAIL, "Unexpected success")
		except:
			# restore the working configuration
			oss[0].unconfigure_lustre()
			oss_net = {'tcp': [oss_intfs[0]]}
			oss[0].configure_net(oss_net)
			oss[0].commit()
			oss[0].configure_lustre(lustrefs.get_mgs_nids())
			# wait before returning. The intent is to give the
			# FS sometime to recover, so the subsequent tests
			# run
			sleep(300)
			return lutfrc(LUTF_TEST_PASS)
		return lutfrc(LUTF_TEST_FAIL, "Write successful even though dynamic NIDs are disabled.")
	except Exception as e:
		raise e


