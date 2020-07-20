"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- Configure 3 NIs on the same network
- Configure the peer with the same NIDs
- Send 1 message which requires a response from peer NID
- Confirm that responses are being sent to the same NI
"""

import os,re
import yaml, random
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lutf_file import LutfFile
from lnet_selftest import LNetSelfTest
from lustre_logs import LustreLog, LNET_TRACE_MSG_SEND, LNET_TRACE_MSG_RECV

def run():
	la = agents.keys()
	if len(la) < 2:
		return lutfrc(LUTF_TEST_SKIP, "Not enough agents to run the test")
	t1 = LNetHelpers(target=la[0])
	t2 = LNetHelpers(target=la[1])
	try:
		t1.configure_lnet()
		t1.configure_net('tcp1')
		t1.set_discovery(0)
		peer_nids1 = t1.list_nids()
		t2.configure_lnet()
		t2.configure_net('tcp1')
		t2.set_discovery(0)
		peer_nids2 = t2.list_nids()
		nids = ','.join(peer_nids2[1:])
		t1.api_config_peer(prim_nid=peer_nids2[0], nids=nids)
		nids = ','.join(peer_nids1[1:])
		t2.api_config_peer(prim_nid=peer_nids1[0], nids=nids)
		# enable logs
		logs = LustreLog(target=la[0])
		logs.add_level('net')
		logs.start()
		# send ping
		t1.ping(peer_nids2[0])
		# disable and extract log
		rc = logs.stop()
		parsed_logs = logs.get_log()
		trace = logs.extract('TRACE', parsed_logs)
		send_pattern = LNET_TRACE_MSG_SEND
		recv_pattern = LNET_TRACE_MSG_RECV
		# verify via TRACE that responses are correct
		# I'm expected a GET followed by a reply. Let's find the
		# GET
		result = None
		j = 0
		for i in range(0, len(trace)):
			line = trace[i]
			j += 1
			if ": GET" in line and "lnet_handle_send" in line:
				result = re.search(send_pattern, line)
				break
		if not result:
			return lutfrc(LUTF_TEST_FAIL, "Failed to parse the logs")
		src_nid = result[11]
		txni_nid = result[12]
		sd_src_nid = result[13]
		msg_dst_nid = result[14]
		txpeer_lpni_nid = result[15]
		sd_rtr_nid = result[16]
		msg_type = result[17]
		retr_count = result[18]
		# find the REPLY
		result = None
		start = len(trace) - j
		for i in range(start, len(trace)):
			line = trace[i]
			if 'REPLY' in line and "lnet_parse" in line:
				result = re.search(recv_pattern, line)
				break
		if not result:
			return lutfrc(LUTF_TEST_FAIL, "Failed to parse the logs")
		recv_dest_nid = result[11]
		recv_ni_nid = result[12]
		recv_src_nid = result[13]
		recv_msg_type = result[14]
		recv_path = result[15]

		if src_nid != recv_dest_nid and msg_dst_nid != recv_src_nid:
			return lutfrc(LUTF_TEST_FAIL, "message send/recved on wrong NIDs", sentfrom=src_nid,
				receivedon=recv_dest_nid, sento=msg_dst_nid, receivedfrom=recv_src_nid)
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		t1.uninit()
		t2.uninit()
		raise e

