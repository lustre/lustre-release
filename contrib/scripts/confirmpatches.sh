#!/bin/bash
PROG=$(basename $0)
[ "$1" = "-h" -o "$1" = "--help" ] && echo "usage: $PROG [patch dir]" && exit 0
[ "$1" = "-v" ] && shift && VERBOSE="echo" || VERBOSE=":"

[ "$1" ] && BASEDIR="$1"
BASEDIR=${BASEDIR:-lustre/kernel_patches}
SERIESPATH=${SERIESPATH:-$BASEDIR/series}
PATCHPATH=${PATCHPATH:-$BASEDIR/patches}

[ ! -d "$BASEDIR" ] && echo "$PROG: missing base directory '$BASEDIR'" && exit 1
[ ! -d "$SERIESPATH" ] && echo "$PROG: missing series '$SERIESPATH'" && exit 2
[ ! -d "$PATCHPATH" ] && echo "$PROG: missing patches '$PATCHPATH'" && exit 3

for SERIES in $(ls $SERIESPATH | egrep -v "~$|.orig|.rej") ; do
	$VERBOSE "series: $SERIES"
	for PATCH in $(grep -v "^#" $SERIESPATH/$SERIES); do
		$VERBOSE $PATCH
		if [ ! -e $PATCHPATH/$PATCH ]; then
			echo "$SERIESPATH/$SERIES: patch '$PATCH' not found!"
		fi
	done
done
