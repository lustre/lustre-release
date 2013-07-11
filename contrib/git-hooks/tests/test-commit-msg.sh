#!/bin/bash

program=$0
progdir=$(\cd $(dirname $0) >/dev/null && pwd)

die() {
	echo "$program fatal error:  $*"
	exit 1
} 1>&2

TEMPFILE=$(mktemp ${TMPDIR:-.}/commit-XXXXXX)
test -f "$TEMPFILE" || die "mktemp fails"
trap "rm -f $TEMPFILE COMMIT*" EXIT

# Pass through xtrace setting to commit-msg script
#
SHELL=${SHELL:-sh}
shopt -qo xtrace && SHELL+=' -x'

test $# -eq 0 && set -- ${progdir}/commit.*

export FAIL=""
readonly report_fmt='%-20s %s\n'
for f; do
	case "$f" in
	( *.orig | *.rej ) continue ;;
	esac

	cp $f $TEMPFILE
	results=$(exec 2>&1 ${SHELL} $progdir/../commit-msg $TEMPFILE)
	case $'\n'"$results" in
	( *$'\nerror:'* ) OK=0 ;;
	( * ) OK=1 ;;
	esac

	f=$(basename $f)
	case $OK${f#*commit.} in
	1ok*)	printf "$report_fmt" $f: "PASS (was allowed)" ;;
	0ok*)	printf "$report_fmt" $f: "FAIL (not allowed)"; FAIL="$FAIL $f";;
	0*)	printf "$report_fmt" $f: "PASS (found error)" ;;
	*)	printf "$report_fmt" $f: "FAIL (no error)"   ; FAIL="$FAIL $f";;
	esac
done

if [ -n "$FAIL" ]; then
	echo -e "\nerror: commit-msg test(s) failed!" 1>&2
	echo "	 $FAIL"
fi

rm -f $TEMPFILE $TEMPFILE.*

## Local Variables:
## Mode: shell-script
## sh-basic-offset:          8
## sh-indent-after-do:       8
## sh-indentation:           8
## sh-indent-for-case-label: 0
## sh-indent-for-case-alt:   8
## indent-tabs-mode:         t
## End:
