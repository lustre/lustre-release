#!/bin/bash
PROG=$(basename $0)
[ "$1" = "-h" -o "$1" = "--help" ] && echo "usage: $PROG [patch dir]" && exit 0
[ "$1" = "-d" ] && shift && DELETE="git rm" || DELETE="echo"
[ "$1" = "-v" ] && shift && VERBOSE="echo" || VERBOSE=":"

[ "$1" ] && BASEDIR="$1"
BASEDIR=${BASEDIR:-lustre/kernel_patches}
SERIESPATH=${SERIESPATH:-$BASEDIR/series}
PATCHPATH=${PATCHPATH:-$BASEDIR/patches}

[ ! -d "$BASEDIR" ] && echo "$PROG: missing base directory '$BASEDIR'" && exit 1
[ ! -d "$SERIESPATH" ] && echo "$PROG: missing series '$SERIESPATH'" && exit 2
[ ! -d "$PATCHPATH" ] && echo "$PROG: missing patches '$PATCHPATH'" && exit 3

for PATCH in $(ls $PATCHPATH | egrep -v "CVS|~$|.orig|.rej"); do
	$VERBOSE $PATCH
 	if ! grep -q $PATCH $SERIESPATH/*.series ; then
	  	$DELETE $PATCHPATH/$PATCH
	fi
done
