"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- Configure 2 NIs with different NUMA distance
- Send three or more messages
- check stats confirming messages sent over the nearest NI (NUMA wise)
- add another NI which is close NUMA wise than the current nearest
- check stats confirming messages sent over the newly addded NI
"""

import os
import yaml, random, threading, time
import lnetconfig
from lutf import agents, me
from lutf_basetest import *
from lnet import TheLNet
from lutf_exception import LUTFError
from lnet_helpers import LNetHelpers
from lutf_file import LutfFile
from lnet_selftest import LNetSelfTest

def run():
	return lutfrc(LUTF_TEST_SKIP, "NUMA tests currently not implemented")

