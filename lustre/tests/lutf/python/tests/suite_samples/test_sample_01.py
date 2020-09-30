"""
@PRIMARY: s01
@PRIMARY_DESC: Illustrate the run() function needed by the LUTF to execute the script.
@SECONDARY: s02
@DESIGN: N/A
@TESTCASE: Print a message and return success
"""

from lutf_basetest import *

def run():
	print("Hello Lustre")
	return lutfrc(LUTF_TEST_PASS)
