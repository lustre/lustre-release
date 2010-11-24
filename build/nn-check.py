#!/usr/bin/python

# This script is for checking that patches don't introduce non-portable symbols
# into the Lustre/LNET/libcfs code.
#
# Input:
# 1. (Required) Filename (including path) of the diff file to be checked
# 2. (Optional) path to the nn-final-symbol-list.txt file (By default, this
#    script looks for nn-final-symbol-list.txt in the current working
#    directory.)
#
# Output:
# The output of this script is either PASS or FAIL (with WARNINGS).
# FAIL means that there may have been symbols found that are not supposed
# to be used.  This requires the person running the script to look into the
# WARNINGS that are in the output to determine if there is a problem.

# Author: lisa.week@sun.com

import string
import re
import sys
import optparse
import os.path
import fileinput

# Setup command line options for nn-check.py
from optparse import OptionParser
usage = "%prog DIFF-FILE [options]"
parser = OptionParser(usage)
parser.add_option("-s", "--symb", action="store", dest="symb_pathname",
		  help="(Optional) PATH to nn-final-symbol-list.txt file",
		  metavar="PATH")

(options, args) = parser.parse_args()

# Check if we have the minimum number of arguments supplied. 
if len(args) < 1:
	parser.error("Incorrect number of arguments, see nn-check -h for help.")

# Check if we were passed a path to the nn-final-symbol-list.txt file
if options.symb_pathname:
	symb_file = os.path.join(options.symb_pathname,
                                 'nn-final-symbol-list.txt')
else:
	symb_file = 'nn-final-symbol-list.txt'

# Global Variables
bad_symbol_cnt = 0
symbol_dict = dict() 

# Function Definitions
def search_symbol(line, linenum):
	global bad_symbol_cnt

	for key, val in symbol_dict.items():
		regex_match = val.search(line)

		if regex_match:
			print_symbol = regex_match.group(0)
			print 'warning: Found %s at line %d:' \
				% (print_symbol, linenum)
			print '%s' % line.rstrip()
			bad_symbol_cnt += 1

# Open the nn-final-symbol-list.txt file and pull in the symbols to check into
# a dictionary object.
try:
	f = fileinput.input(symb_file)
except IOError:
	print 'nn-check.py: error: %s not found.' % symb_file
	print 'Is nn-final-symbol-list.txt is in your current working directory'
	print 'or have you have passed nn-check.py a valid path to the file?'
	sys.exit(1)


for line in f:
	stripped_symbol = line.rstrip()
	symbol_dict[stripped_symbol] = re.compile(stripped_symbol)

# Close nn-final-symbol-list.txt
f.close()

# Open the diff file passed to the script and parse it for the symbols from
# nn-final-symbol-list.txt
try:
	f = fileinput.input(sys.argv[1])
except IOError:
	print 'nn-check.py: error: %s not found.' % sys.argv[1] 
	print 'Check the path provided for the diff file.'
	sys.exit(1)

# The main portion of the script
print '==================================================='
print '%s: starting nn-check' % sys.argv[1]
print '==================================================='

index = re.compile(r'^\+\+\+ b/(.*)')
plus = re.compile(r'^\+')
for line in f:
	# Check for the "diff --cc " delimiter in order to grab the file name.
	index_match = index.match(line)

	if index_match:
		# Store the file name
		filename=index_match.group(1)
		print '%s: ' % filename
	else:
		# Check if the line starts with a "+" character.
		plus_match = plus.match(line)
		if plus_match:
			# The line starts with a "+" character.  Look for
			# non-portable symbols
			search_symbol(line, f.lineno())
		else:
			continue

# Close the diff file
f.close()

# Finish up and print the results of the script (i.e. total number of
# bad symbols found)
if bad_symbol_cnt != 0:
	print '=============================='
	print 'Finished nn-check status: FAIL'
	print '=============================='
	print 'Found %d potential problem(s).  See "WARNINGS" from script output and refer to https://wikis.lustre.org/intra/index.php/Lustre_Name_Normalization for the complete set of rules to make sure you have not used a non-portable symbol.' % bad_symbol_cnt
else:
	print '=============================='
	print 'Finished nn-check status: PASS'
	print '=============================='
