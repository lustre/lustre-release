#!/bin/bash

set -e

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

MOUNT=${MOUNT:-/mnt/lustre}
DIR=${DIR:-$MOUNT}
export NAME=$NAME
clean() {
        echo -n "cln.."
        sh llmountcleanup.sh > /dev/null || exit 20
}
CLEAN=${CLEAN:-clean}
start() {
        echo -n "mnt.."
        sh llrmount.sh > /dev/null || exit 10
        echo "done"
}
START=${START:-start}

log() {
	echo "$*"
	lctl mark "$*" || /bin/true
}

pass() {
    echo PASS
}

mount | grep $MOUNT || sh llmount.sh

log '== drop ldlm request  ======================== test 1'
echo 0x302 > /proc/sys/lustre/fail_loc
echo 3 > /proc/sys/lustre/timeout
touch $DIR/f &
sleep 5
echo 0 > /proc/sys/lustre/fail_loc
lctl --device 6 recover
pass
$CLEAN
$START

log '== drop ldlm reply (bug 1139) ================ test 2'
echo 0x213 > /proc/sys/lustre/fail_loc
echo 3 > /proc/sys/lustre/timeout
touch $DIR/f
pass
$CLEAN
$START

log '== drop reply after completion (bug 1068) ==== test 3'
touch $DIR/f
stat $DIR/f
echo 0x213 > /proc/sys/lustre/fail_loc
echo 3 > /proc/sys/lustre/timeout
echo foo >> $DIR/f
pass
$CLEAN
$START
