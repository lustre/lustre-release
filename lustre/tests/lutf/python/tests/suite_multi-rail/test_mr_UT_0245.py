"""
@PRIMARY: cfg-035
@PRIMARY_DESC: If no CPT to NI mapping is configured via the DLC API, LNet shall associate the NI with all existing CPTs.
@SECONDARY: cfg-040, cfg-045, cfg-055, cfg-060, cfg-065
@DESIGN: N/A
@TESTCASE:
- initialize the system
- Configure 3 NIs with different NUMA distance
- Set the NUMA range to a higher value
- Send three or more messages
- check stats confirming all NIs being used to send messages
- Delete an NI
- check stats confirming deleted NI not being used and message drop count is 0
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

