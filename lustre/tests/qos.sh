#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test:
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-""}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# The QOS tests need two nodes. The first acts as server (variable SERVER),
# the second as client only.
# The principle behind the QOS unit test is:
# 1) create an unbalanced situation on SERVER
# 2) perform opertion on CLIENT to trigger QOS information update
# 3) verify usage of new QOS information on CLIENT
SERVER=${SERVER:-`hostname`}
# must change client to a valid hostname
CLIENT=${CLIENT:-""}

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

LFIND=${LFIND:-lfind}
LSTRIPE=${LSTRIPE:-lstripe}
LCTL=${LCTL:-lctl}
RSH=${RSH:-rsh}
CHECKSTAT=${CHECKSTAT:-"checkstat -v"}

QOSPROC="/proc/sys/lustre"

export NAME=${NAME:-qos-config}

SAVE_PWD=$PWD
FULL_SRCDIR=${SAVE_PWD}/${SRCDIR}

clean() {
	echo -n "cln.."
	${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; NAME=${NAME} NODE=client sh ./llmountcleanup.sh" || exit 20
	sh llmountcleanup.sh > /dev/null || exit 21
	I_MOUNTED=no
}
CLEAN=${CLEAN:-clean}

start() {
	echo -n "mnt.."
	sh llrmount.sh > /dev/null || exit 10
	${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; NAME=${NAME} NODE=client sh ./llrmount.sh" || exit 11
	I_MOUNTED=yes
	echo "done"
}
START=${START:-start}

log() {
	echo "$*"
	lctl mark "$*" 2> /dev/null || true
}

run_one() {
	if ! mount | grep -q $DIR; then
		$START
	fi
	log "== test $1: $2"
	test_$1 || error "test_$1: $?"
	pass
	cd $SAVE_PWD
	$CLEAN
}

build_test_filter() {
        for O in $ONLY; do
            eval ONLY_${O}=true
        done
        for E in $EXCEPT $ALWAYS_EXCEPT; do
            eval EXCEPT_${E}=true
        done
}

_basetest() {
    echo $*
}

basetest() {
    IFS=abcdefghijklmnopqrstuvwxyz _basetest $1
}

run_test() {
         base=`basetest $1`
         if [ "$ONLY" ]; then
                 testname=ONLY_$1
                 if [ ${!testname}x != x ]; then
 			run_one $1 "$2"
 			return $?
                 fi
                 testname=ONLY_$base
                 if [ ${!testname}x != x ]; then
                         run_one $1 "$2"
                         return $?
                 fi
                 echo -n "."
                 return 0
 	fi
        testname=EXCEPT_$1
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1"
                 return 0
        fi
        testname=EXCEPT_$base
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1 (base $base)"
                 return 0
        fi
        run_one $1 "$2"
 	return $?
}

error() { 
	log "FAIL: $@"
	exit 1
}

pass() { 
	echo PASS
}

[ -z "${CLIENT}" ] && echo "CLIENT must not be empty"  && exit 96

MOUNT="`mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
if [ -z "$MOUNT" ]; then
	sh llmount.sh
	MOUNT="`mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
	[ -z "$MOUNT" ] && error "NAME=$NAME not mounted"
	I_MOUNTED=yes
	${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; NAME=${NAME} NODE=client sh ./llrmount.sh" || exit 97
	CLIENT_MOUNT="`${RSH} ${CLIENT} mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
	[ -z "${CLIENT_MOUNT}" ] && echo "NAME=${NAME} not mounted on remote client ${CLIENT}"  && exit 98
fi

[ `echo $MOUNT | wc -w` -gt 1 ] && error "NAME=$NAME mounted more than once"

DIR=${DIR:-$MOUNT}
[ -z "`echo $DIR | grep $MOUNT`" ] && echo "$DIR not in $MOUNT" && exit 99

LOVNAME=`cat /proc/fs/lustre/llite/fs0/lov/common_name`
STRIPECOUNT=`cat /proc/fs/lustre/lov/$LOVNAME/numobd`

rm -rf $DIR/[Rdfs][1-9]*

build_test_filter

test_0() {
    cat ${QOSPROC}/QoS_statfs_interval || error
    cat ${QOSPROC}/QoS_rescan_interval || error
    cat ${QOSPROC}/QoS_update_interval || error
    cat ${QOSPROC}/QoS_freeblock_imbalance || error
    cat ${QOSPROC}/QoS_freeblock_percent || error
    cat ${QOSPROC}/QoS_nobjects_imbalance || error
}
run_test 0 "cat ${QOSPROC}/QoS_*"

test_1() {
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_statfs_interval || error
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_rescan_interval || error
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_update_interval || error
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_freeblock_imbalance || error
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_freeblock_percent || error
    ${RSH} ${CLIENT} cat ${QOSPROC}/QoS_nobjects_imbalance || error
}
run_test 1 "${RSH} ${CLIENT} cat ${QOSPROC}/QoS_*"

TMPDIR=$OLDTMPDIR
TMP=$OLDTMP
HOME=$OLDHOME

log "cleanup: ======================================================"
CLIENT_MOUNT="`${RSH} ${CLIENT} mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
if [ "${CLIENT_MOUNT}" ]; then
	${RSH} ${CLIENT} "cd ${FULL_SRCDIR}; NAME=${NAME} NODE=client sh ./llmountcleanup.sh" || error
fi
if [ "$I_MOUNTED" = "yes" -a "`mount | grep ^$NAME`" ]; then
	rm -rf $DIR/[Rdfs][1-9]*
	sh llmountcleanup.sh || error
fi

echo '=========================== finished ==============================='
