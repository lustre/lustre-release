#!/usr/bin/python

import sys
import re
import string

#TODO
# clean up rest/file
# clean up +6 and like (assumptions). should be turned into 'find'
# make regession tests for all cases (Only in, etc)

try:
        filename = sys.argv[1]
except:
        print 'requires a file name'
        sys.exit(1)

filefd = open(filename)
file = filefd.read()
filefd.close()

rest = file
pat = "(^(?:diff .*\n)?--- .*\n\+\+\+ .*)?\n@@ -(\d+),?(\d+)? \+(\d+),?(\d+)? @@|^(Only in .*)"
startpat = re.compile(pat, re.M)

pos = 0
oldpos = 0
filelen = len(rest)
oldrest = ""
while(1):
        rexp = startpat.search(rest)
        if not rexp:
                break

	if rexp.group(6):
		print rexp.group(6)
		rest = rest[rexp.end(6)+1:]
		continue
		
	header = rexp.group(1)
        orgfile_start = string.atoi(rexp.group(2))
	if rexp.group(3):
		orgfile_len = string.atoi(rexp.group(3))
	else:
		orgfile_len = -1
        newfile_start = string.atoi(rexp.group(4))
	if rexp.group(5):
		newfile_len = string.atoi(rexp.group(5))
	else:
		newfile_len = -1
        rest = rest[rexp.start(2):]
        rest = rest[string.find(rest, "\n")+1:]

	rexp2 = startpat.search(rest)
	if rexp2:
		if rexp2.start(6) != -1:
			oldrest = rest[rexp2.start(6)-1:]
			rest = rest[:rexp2.start(6)]
		elif rexp2.start(1) == -1:
			oldrest = rest[rexp2.start(2)-5:]
			rest = rest[:rexp2.start(2)-4]
		else:
			oldrest = rest[rexp2.start(1)-1:]
			rest = rest[:rexp2.start(1)]
	else:
		oldrest = rest

#	pos = filelen - len(oldrest)
#	if pos - oldpos > 100:
#		sys.stderr.write(`pos`+'/'+`filelen`+'\n')
#		oldpos = pos

	first = 1
	oldminuses = 0
	oldplusses = 0
	oldoffset = 0
	while(1):
		#erstat early line stuff med lookbehind paa {1,2}-dims
		#nedenfor RAA
	        linepat = "^([^-+\n]*)\n?(((^[-+].*\n)|^(.*\n){1,2}(?=^[-+].*\n))+)(.*)\n?"
		compat = re.compile(linepat, re.M)
	        rexp = compat.search(rest)
	        if not rexp:
	                break

		prematch = rexp.group(1)
	        match = rexp.group(2)
		muddle = len(match)

#		print rest
#		print 'prematch ', rexp.start(1), rexp.end(1), prematch
#		print 'match ---------'
#		print match
#		print 'match --------'

		# dump unwanted early lines...
		if match[0] != "+" and match[0] != "-":
			while(1):
				next = string.find(match, '\n')
				if next == -1:
					break
				if match[next+1] == "+" or match[next+1] == "-":
					prematch = match[:next]
					match = match[next+1:]
					break
				match = match[next+1:]


#		print 'prematch ', rexp.start(1), rexp.end(1), len(prematch)
#		print '('+prematch+')'
#		if prematch == ' ':
#			print 'space'
		muddle = muddle - len(match)

	        lines = string.count(match, "\n")
		compat = re.compile("^-", re.M)
	        minuses = len(compat.findall(match))
		compat = re.compile("^\+", re.M)
	        plusses = len(compat.findall(match))
	        orgsize = minuses + 2 + (lines - minuses - plusses)
	        newsize = plusses + 2 + (lines - minuses - plusses)

		noeol = "^(\\\ No newline at end of file)$"
		compnoeol = re.compile(noeol, re.M)
		if compnoeol.search(match) or compnoeol.search(rexp.group(6)):
			orgsize = orgsize - 1
			newsize = newsize - 1
			
		coherent = 0
		if lines - plusses == 0:
			coherent = 1
		elif lines - minuses == 0:
			coherent = 1

		# RAA FIXME
		if not len(prematch):#or len(prematch) == 1 and prematch == ' ':
			orgsize = orgsize -1
			newsize = newsize -1
		if rexp.start(6) == rexp.end(6):
			orgsize = orgsize -1
			newsize = newsize -1

#	        print "lines in match: ", lines
#	        print "number of minuses: ", minuses
#	        print "number of plusses: ", plusses
	
	        matchpos = rexp.start(2) + muddle
	        offset =  string.count(rest[:matchpos], "\n")

#		print 'offset/oldoffset: ', offset,oldoffset
#		print 'oldplusses/oldminuses: ', oldplusses, oldminuses
#		print 'orgfile_start/newfile_start: ', orgfile_start, newfile_start

	        orgstart = orgfile_start + offset + oldoffset - oldplusses
	        newstart = newfile_start + offset - oldminuses + oldoffset

		# RAA: Bwadr. Fix antagelse om prematch paa en anden
		# maade
		orgstartmod = 0
		newstartmod = 0
		if orgfile_start == 1 and not len(prematch):
			orgstartmod = 1
		if newfile_start == 1 and not len(prematch):
			newstartmod = 1
		if orgfile_start == 0 and orgfile_len == 0:
			orgstartmod = 1
			# RAA Hack!
			plusses = plusses + 1
			minuses = minuses +1
		if newfile_start == 0 and newfile_len == 0:
			newstartmod = 1
			# RAA Hack!
			plusses = plusses + 1
			minuses = minuses +1
		
		if header and first:
			print header
			first = 0

		# should the start(1) == 0 be orgstart == 1? RAA
	        if orgstart == 1 and newstart == 1 and plusses == 0 and coherent:
	                print "@@ -"+`orgstart`+","+`orgsize`+" +"+`newstart`+" @@"
	                print match[:string.rfind(match, "\n")]
	                print rexp.group(6)
	        elif rexp.start(6) == rexp.end(6) and plusses == 0 and coherent:
			if orgstartmod:
				orgstart = orgstart + 1
			if newstartmod:
				newstart = newstart + 1
	                print "@@ -"+`orgstart-1`+","+`orgsize`+" +"+`newstart-1`+" @@"
	                print prematch
	                print match[:string.rfind(match, "\n")]
	        elif orgstart == 1 and orgstart == 1 and minuses == 0 and coherent:
	                print "@@ -"+`orgstart`+" +"+`newstart`+","+`newsize`+" @@"
	                print match[:string.rfind(match, "\n")]
	                print rexp.group(6)
	        elif rexp.start(6) == rexp.end(6) and minuses == 0 and coherent:
			if orgstartmod:
				orgstart = orgstart + 1
			if newstartmod:
				newstart = newstart + 1
	                print "@@ -"+`orgstart-1`+" +"+`newstart-1`+","+`newsize`+" @@"
	                print prematch
	                print match[:string.rfind(match, "\n")]
	        else:
			if orgstartmod:
				orgstart = orgstart + 1
			if newstartmod:
				newstart = newstart + 1
	                print "@@ -"+`orgstart-1`+","+`orgsize`+" +"+`newstart-1`+","+`newsize`+" @@"
			if len(prematch):
				print prematch
	                print match[:string.rfind(match, "\n")]
			if rexp.start(6) != rexp.end(6):
	                	print rexp.group(6)
	
        	rest = rest[rexp.end(6):]
		oldminuses = minuses + oldminuses
		oldplusses = plusses + oldplusses
		oldoffset = oldoffset + offset + lines #include match()-lines


	rest = oldrest
