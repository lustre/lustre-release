"""
@PRIMARY: s02
@PRIMARY_DESC: Illustrate the lutfrc() function and how it's used to return values to be stored in the
global results database.
@SECONDARY: N/A
@DESIGN: N/A
@TESTCASE: return success and 2 key/value pairs
"""

from lutf_basetest import lutfrc
import datetime

def run():
	print("Hello Lustre")
	return lutfrc(0, name='Lustre', date=datetime.datetime.now())
