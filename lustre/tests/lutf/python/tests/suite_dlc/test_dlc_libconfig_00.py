"""
@PRIMARY: N/A
@PRIMARY_DESC: N/A
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: Test liblnetconfig LNet initialization API
"""

import lnetconfig
from lutf_exception import *
from lutf_basetest import *

def run():
	success = False
	rc = lnetconfig.lustre_lnet_config_lib_init()
	if (rc == lnetconfig.LUSTRE_CFG_RC_NO_ERR):
		success = True
	else:
		success = False
	lnetconfig.lustre_lnet_config_lib_uninit()
	if not success:
		LUTFError("Failed to initialize LNet")

	return lutfrc(LUTF_TEST_PASS)
