#!/bin/bash
PROG=$(basename $0)
[ "$1" = "-h" -o "$1" = "--help" ] && echo "usage: $PROG [patch dir]" && exit 0
[ "$1" = "-d" ] && shift && DELETE="git rm" || DELETE="echo Unused"
[ "$1" = "-v" ] && shift && VERBOSE="echo Checking" || VERBOSE=":"

[ "$1" ] && BASEDIR="$1"
BASEDIR=${BASEDIR:-lustre/kernel_patches}
SERIESPATH=${SERIESPATH:-$BASEDIR/series}
PATCHPATH=${PATCHPATH:-$BASEDIR/patches}

[ ! -d "$BASEDIR" ] && echo "$PROG: missing base directory '$BASEDIR'" && exit 1
[ ! -d "$SERIESPATH" ] && echo "$PROG: missing series '$SERIESPATH'" && exit 2
[ ! -d "$PATCHPATH" ] && echo "$PROG: missing patches '$PATCHPATH'" && exit 3

CANONICAL_SERIESPATH=$(readlink -f ${SERIESPATH})
pushd $PATCHPATH > /dev/null
for PATCH in $(find -name "*.patch"); do
	# Remove the leading "./"
	PATCH=${PATCH##./}
	$VERBOSE $PATCH
	if ! grep -q -e "^$PATCH" $CANONICAL_SERIESPATH/*.series ; then
		$DELETE $PATCH
	fi
done
popd > /dev/null
