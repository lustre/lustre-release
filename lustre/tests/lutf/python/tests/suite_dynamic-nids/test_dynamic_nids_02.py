"""
@PRIMARY: LU-10360-03
@PRIMARY_DESC: Allow clients to continue using servers which have
changed their IP address during a boot cycle
@DESIGN:
An IR log is sent with the current NID information of the server. When the
client receives the IR log it checks the entry there against what it has already
stored from the llog.
  If the entry is not there, then add a new connection to the import
  If the entry is there but the NID list is different, then update the NID
  information with the latest NID information provided in the IR log.
Since allowing new servers NIDs previously unknown during the initial mount to
be used, it could be considered a security risk on some sites.
  Add a new File system level module parameter to enable this feature.
  The feature is disabled by default. To Enable the feature:
      lctl set_param mgc.*.dynamic_nids=1
@TESTCASE:
    Setup a file system consistent of:
        1 node: MGS/MDS
        1 node: OSS should have 2 IP addresses
        1 node: Client
    Mount the File System and the client
        Use only one of the IP addresses on the OSS
    Enable the dynamic_nids feature on both the MDS and the client
    Write multiple files to the FS
    Read back the files and make sure they are correct
    unmount the OSS and remove lustre modules
    Change the OSS configuration to use the other IP address for NID
    load lustre on the OSS and re mount
    LS the file system.
        We should get the exact same list of files
    Write more files and read them back.
        the write/read operation should succeed
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

def set_check_dynamic_nids(node, prev, new):
	dn = node.get_dynamic_nids()
	if dn != prev:
		return False, prev
	node.set_dynamic_nids(new)
	dn = node.get_dynamic_nids()
	if dn != new:
		return False, new
	return True, new

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
		# configure the OSS to use the first IP address
		MGSs = lustrefs.get_mgs_nodes()
		OSSs = lustrefs.get_oss_nodes()
		clients = lustrefs.get_client_nodes()
		if len(MGSs) < 1 or len(OSSs) < 1 or len(clients) < 1:
			return lutfrc(LUTF_TEST_SKIP, "Unexpected cluster: MGSs %d, OSSs %d, clients %d" % (len(MGSs), len(OSSs), len(clients)))

		oss = lustrefs.get_oss_nodes()
		oss_intfs = oss[0].list_intfs()
		if len(oss_intfs) <= 1:
			return lutfrc(LUTF_TEST_SKIP, "not enough interfaces on oss %s (%s)" % (oss[0].get_node_name(), oss[0].get_node_hostname()))
		oss_net = {'tcp': [oss_intfs[0]]}
		lustrefs.configure_nets(oss=oss_net)
		lustrefs.mount_servers(num_mgs=1, num_oss=1)
		lustrefs.mount_clients(num=1)
		rc, value = set_check_dynamic_nids(MGSs[0], 0, 1)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "expected dynamic_nids to be set to: " + str(value))
		rc, value = set_check_dynamic_nids(clients[0], 0, 1)
		if not rc:
			return lutfrc(LUTF_TEST_FAIL, "expected dynamic_nids to be set to: " + str(value))
		rc, f = write_verify_to_fs(lustrefs)
		if not rc:
			lutfrc(LUTF_TEST_FAIL, "Failed to verify data on " + f)
		logging.debug("unconfigure lustre on: " + oss[0].get_node_name())
		oss[0].unconfigure_lustre()
		oss_net = {'tcp': [oss_intfs[1]]}
		oss[0].configure_net(oss_net)
		oss[0].commit()
		sleep(10)
		logging.debug("configure lustre on: " + oss[0].get_node_name())
		oss[0].configure_lustre(lustrefs.get_mgs_nids())
		sleep(10)
		try:
			rc, f = write_verify_to_fs(lustrefs)
			if not rc:
				lutfrc(LUTF_TEST_FAIL, "Failed to verify data on " + f)
		except:
			return lutfrc(LUTF_TEST_FAIL, "Couldn't write the file system")
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		raise e


