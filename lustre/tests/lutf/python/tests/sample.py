"""
@PRIMARY: Primary Requirement ID
@PRIMARY_DESC: Textual description of the primary requirement
@SECONDARY: Secondary Requirement IDs if applicable
@DESIGN: Design details
@TESTCASE: Test case description
"""

from lutf_basetest import BaseTest, lutfrc
from lutf_exception import LUTFError

class SampleTestClass(BaseTest):
	def __init__(self, target=None):
		super().__init__(os.path.abspath(__file__),
				 target=target)

def run():
	raise LUTFError("Replace with your code")
	return lutfrc(0)
