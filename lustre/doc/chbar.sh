#! /bin/sh
#	Gadget to take two LaTeX files and produce a third which
#	has changebars highlighting the difference between them.
#
# Version 1.1
# Author:
#	Don Ward, Careful Computing (don@careful.co.uk)
# v1.0	April 1989
# v1.1  Feb 93	Amended to use changebar.sty (v3.0) and dvips
#
# Useage:
#	chbar file1 file2 [output]
#		(default output is stdout)
#	chbar old
#		(new file on stdin, output on stdout)
#
# Method:
# 1	Use diff to get an ed script to go from file1 to file2.
# 2	Breathe on it a bit (with sed) to insert changebar commands.
# 3	Apply modified ed script to produce (nearly) the output.
# 4	Use awk to insert the changebars option into the \documentstyle
#	and to handle changebar commands inside verbatim environments.
# 5     Remove changebars before \begin{document} with sed
if test $# -eq 0
then cat <<\xEOF
Useage:
	chbars old new [output]
	chbars old
xEOF
exit 0
fi
#	Strictly speaking, should check that $TMP doesn't exist already.
TMP=/tmp/chb-$$
export TMP
OLD=$1
if test $# -eq 1
then   NEW="-"; 	# arg is old file, take new from stdin
else   NEW=$2 ; 
fi  
#
#	sed commands to edit ed commands to edit old file
cat <<\xEOF > $TMP
/^\.$/i\
\\cbend{}%
/^[0-9][0-9]*[ac]$/a\
\\cbstart{}%
/^[0-9][0-9]*,[0-9][0-9]*[ac]$/a\
\\cbstart{}%
/^[0-9][0-9]*d$/a\
i\
\\cbdelete{}%\
.
/^[0-9][0-9]*,[0-9][0-9]*d$/a\
i\
\\cbdelete{}%\
.
xEOF
diff -b -e $OLD $NEW | ( sed -f $TMP ; echo w ${TMP}1 ; echo q ) | ed - $OLD
#	awk commands to insert Changebars style and to protect
#	changebar commands in verbatim environments
#       and to tell what driver is in use
cat <<\xEOF >$TMP
/^\\documentstyle/{
  if (index($0, "changebar") == 0 ) {
    opts = index($0, "[")
    if (opts > 0)
	printf "%schangebar,%s",substr($0,1,opts),substr($0,opts+1)
    else
	printf "\\documentstyle[changebar]%s\n", substr($0,15)
    next
  }
}
/\\begin{document}/ {print "%\\driver{dvips}"}
/\\begin{verbatim}/{++nesting}
/\\end{verbatim}/{--nesting}
/\\cbstart{}%|\\cbend{}%|\cbdelete{}%/ {
  if ( nesting > 0) {
#	changebar command in a verbatim environment: Temporarily exit,
#	do the changebar command and reenter.
#
#	The obvious ( printf "\\end{verbatim}%s\\begin{verbatim} , $0 )
#	leaves too much vertical space around the changed line(s).
#	The following magic seeems to work
#
	print  "\\end{verbatim}\\nointerlineskip"
	print  "\\vskip -\\ht\\strutbox\\vskip -\\ht\\strutbox"
	printf "\\vbox to 0pt{\\vskip \\ht\\strutbox%s\\vss}\n", $0
	print  "\\begin{verbatim}"
	next
	}
}
{ print $0 }
xEOF
awk -f $TMP ${TMP}1 >${TMP}2
#    sed commands to clean up unwanted changebars
#    (those before \begin{document})
# cat <<xEOF >$TMP
# 1,/\\begin{document}/s/\\\\cb[sed][tne][adl][^{}]*{}%$/%/
# xEOF
# if test $# -le 2 || test $3 = '-'
# then  sed -f $TMP ${TMP}2
# else  sed -f $TMP ${TMP}2 >$3
# fi
#rm $TMP ${TMP}[0-9]
cat ${TMP}2
