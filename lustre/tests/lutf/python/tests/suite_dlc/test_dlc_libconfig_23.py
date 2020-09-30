"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: Test dual router setup
Failover to different routers and recovery when router is back up.
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
import lutf_common_def as common

class TestLustreTraffic:
	def __init__(self, target=None):
		self.lh = LNetHelpers(os.path.abspath(__file__), target=target)
		self.sln = SimpleLustreNode(os.path.abspath(__file__), target=target)

def sum_stats(stats, nid, sname):
	fount = False
	total = 0
	for s in stats:
		found = False
		for lpni in s['peer ni']:
			if lpni['nid'] == nid:
				found = True
				break
		if not found:
			continue
		for lpni in s['peer ni']:
			total += lpni['statistics'][sname]
			logging.debug("summing up %s for stat %s value = %d total %d" % (lpni['nid'], sname, lpni['statistics'][sname], total))

	return total

def check_range(percent, cA1, cA2, cB1, cB2):
	usageA = abs(cA2 - cA1)
	usageB = abs(cB2 - cB1)
	diff = abs(usageA - usageB)

	if (diff / usageA) * 100 > percent:
		if usageA > usageB:
			return False, 0
		return False, 1

	if (diff / usageB) * 100 > percent:
		if usageA > usageB:
			return False, 0
		return False, 1

	return True, 0

# return -1 if router is not being used
# return -2 if the router is being used
def check_routed_traffic(oss, rtr, rtr1):
	stats = oss.sln.get_peer_stats()
	rtr_recv_count = sum_stats(stats, rtr.sln.list_nids('tcp2')[0], 'recv_count')
	rtr1_recv_count = sum_stats(stats, rtr1.sln.list_nids('tcp2')[0], 'recv_count')

	sleep(30)
	stats = oss.sln.get_peer_stats()
	rtr_recv_count2 = sum_stats(stats, rtr.sln.list_nids('tcp2')[0], 'recv_count')
	rtr1_recv_count2 = sum_stats(stats, rtr1.sln.list_nids('tcp2')[0], 'recv_count')

	logging.debug('rtr_recv_count = %d rtr_recv_count2: = %d' % (rtr_recv_count, rtr_recv_count2))

	if rtr_recv_count >= rtr_recv_count2:
		return -1, rtr.sln.list_nids('tcp2')[0]

	logging.debug('rtr1_recv_count = %d rtr1_recv_count2: = %d' % (rtr1_recv_count, rtr1_recv_count2))

	if rtr1_recv_count >= rtr1_recv_count2:
		return -1, rtr1.sln.list_nids('tcp2')[0]

	# check that the average change in traffic are approximately
	# equivalent
	rc, rtr_num = check_range(20, rtr_recv_count, rtr_recv_count2, rtr1_recv_count, rtr1_recv_count2)
	if not rc:
		if rtr_num == 0:
			nid = rtr.sln.list_nids('tcp2')[0]
		else:
			nid = rtr1.sln.list_nids('tcp2')[0]
		return -2, nid

	return 0, None

def get_assign_roles(la):
	client = oss = mgs = rtr = rtr1 = None
	for a in la:
		logging.debug('examining: ' + a)
		if re.search('mds(.?)_HOST'.upper(), a.upper()) or re.search('mgs(.?)_HOST'.upper(), a.upper()):
			logging.debug('creating mds on ' + a)
			mgs = TestLustreTraffic(a)
		elif re.search('ost(.?)_HOST'.upper(), a.upper()) or re.search('oss(.?)_HOST'.upper(), a.upper()):
			logging.debug('creating oss on ' + a)
			oss = TestLustreTraffic(a)
		elif re.search('(.?)client(.?)'.upper(), a.upper()) :
			logging.debug('creating client on ' + a)
			client = TestLustreTraffic(a)
		elif re.search('rtr(.?)_HOST'.upper(), a.upper()):
			if not rtr and not rtr1:
				logging.debug('both empty creating rtr on ' + a)
				rtr = TestLustreTraffic(a)
			elif rtr and not rtr1:
				logging.debug('creating rtr1 on ' + a)
				rtr1 = TestLustreTraffic(a)
			elif rtr1 and not rtr:
				logging.debug('creating rtr on ' + a)
				rtr = TestLustreTraffic(a)

	return client, oss, mgs, rtr, rtr1

def run():
	la = agents.keys()
	if len(la) < 5:
		return lutfrc(LUTF_TEST_SKIP, msg="Not enough agents to run routing test. 5 needed %d found" % len(la))

	# setup peer A for lnet_self test
	# setup peer B for lnet_self test
	# setup router
	# run lnet_selftest
	#

	client, oss, mgs, rtr, rtr1 = get_assign_roles(la)

	if not client or not mgs or not oss or not rtr or not rtr1:
		return lutfrc(LUTF_TEST_SKIP, msg="Cluster provided doesn't meet the specification for this test case")

	cur_to = common.get_rpc_timeout()

	try:
		common.set_rpc_timeout(500)
		client.sln.check_down()
		mgs.sln.check_down()
		oss.sln.check_down()
		rtr.sln.check_down()
		rtr1.sln.check_down()

		# setup the networks
		client.sln.configure_net(net_map={'tcp': client.sln.list_intfs()})
		oss.sln.configure_net(net_map={'tcp2': oss.sln.list_intfs()})
		mgs.sln.configure_net(net_map={'tcp2': mgs.sln.list_intfs()})
		tcp_intfs = tcp2_intfs = rtr_intfs = rtr.sln.list_intfs()
		if len(rtr_intfs) > 1:
			tcp_intfs = rtr_intfs[int(len(rtr_intfs)/2):]
			tcp2_intfs = rtr_intfs[:int(len(rtr_intfs)/2)]
		rtr.sln.configure_net(net_map={'tcp': tcp_intfs})
		rtr.sln.configure_net(net_map={'tcp2': tcp2_intfs})

		tcp_intfs = tcp2_intfs = rtr_intfs = rtr1.sln.list_intfs()
		if len(rtr_intfs) > 1:
			tcp_intfs = rtr_intfs[int(len(rtr_intfs)/2):]
			tcp2_intfs = rtr_intfs[:int(len(rtr_intfs)/2)]
		logging.debug(str(tcp_intfs))
		logging.debug(str(tcp2_intfs))
		logging.debug(str(rtr_intfs))
		rtr1.sln.configure_net(net_map={'tcp': tcp_intfs})
		rtr1.sln.configure_net(net_map={'tcp2': tcp2_intfs})

		# setup the routing
		L = TheLNet()
		rt1 = L.make_route(rtr.sln.list_nids('tcp')[0])
		rt2 = L.make_route(rtr1.sln.list_nids('tcp')[0])
		logging.debug(str(rt1), str(rt2))
		client.sln.configure_route({'tcp2': [rt1, rt2]})

		rt1 = L.make_route(rtr.sln.list_nids('tcp2')[0])
		rt2 = L.make_route(rtr1.sln.list_nids('tcp2')[0])
		logging.debug(str(rt1), str(rt2))
		mgs.sln.configure_route({'tcp': [rt1, rt2]})
		oss.sln.configure_route({'tcp': [rt1, rt2]})

		# commit configuration
		rtr.sln.commit()
		rtr.lh.api_set_routing(True)
		rtr1.sln.commit()
		rtr1.lh.api_set_routing(True)
		oss.sln.commit()
		mgs.sln.commit()
		client.sln.commit()

		# setup the cluster
		mgs.sln.configure_lustre()
		oss.sln.configure_lustre(mgs.sln.list_nids('tcp2')[0])
		client.sln.configure_lustre(mgs.sln.list_nids('tcp2')[0])

		# start the traffic
		client.sln.start_traffic(runtime=300)

		# let traffic run for 100 seconds
		sleep(100)

		rc, nid = check_routed_traffic(oss, rtr, rtr1)
		if rc == -1:
			raise LUTFError("router %s is not being used" % (nid))
		if rc == -2:
			raise LUTFError("asymmetric use of routers")

		# turn off one of the routers:
		rtr1.lh.api_set_routing(False)

		# wait for a bit
		sleep(100)
		rc, nid = check_routed_traffic(oss, rtr, rtr1)
		if rc == 0:
			raise LUTFError("1. router %s is still being used" % (str(rtr.sln.list_nids('tcp2'))))

		if rc == -1 and nid != rtr1.sln.list_nids('tcp2'):
			raise LUTFError("2. router %s is still being used" % (str(rtr1.sln.list_nids('tcp2'))))

		if rc == -2 and nid in rtr1.sln.list_nids('tcp2'):
			raise LUTFError("3. router %s:%s is still being used" % (str(nid), str(rtr1.sln.list_nids('tcp2'))))

		client.sln.stop_traffic()
		# unconfigure the file system
		client.sln.unconfigure_lustre()
		oss.sln.unconfigure_lustre()
		mgs.sln.unconfigure_lustre()
		common.set_rpc_timeout(cur_to)
		return lutfrc(LUTF_TEST_PASS)
	except Exception as e:
		client.sln.stop_traffic()
		logging.debug("Handling exception... unconfigure")
		logging.debug("Handling exception... unconfiguring Lustre")
		client.sln.unconfigure_lustre()
		oss.sln.unconfigure_lustre()
		mgs.sln.unconfigure_lustre()
		logging.debug("Handling exception... uninitialize")
		client.lh.uninit()
		oss.lh.uninit()
		mgs.lh.uninit()
		rtr.lh.uninit()
		rtr1.lh.uninit()
		common.set_rpc_timeout(cur_to)
		raise e

