#!/bin/sh

set -e

# attempt to print a useful error location, but the ERR trap isn't
# exported to functions, and the $LINENO doesn't work in EXIT.

trap 'echo ERROR $0:$FUNCNAME:$LINENO: rc: $?' ERR EXIT

LUSTRE=${LUSTRE:-`dirname $0`/..}
LTESTDIR=${LTESTDIR:-$LUSTRE/../ltest}
PATH=$PATH:$LUSTRE/utils:$LUSTRE/tests

RLUSTRE=${RLUSTRE:-$LUSTRE}
RPWD=${RPWD:-$PWD}

. $LTESTDIR/functional/llite/common/common.sh

# XXX I wish all this stuff was in some default-config.sh somewhere
MOUNT=${MOUNT:-/mnt/lustre}
MDSDEV=${MDSDEV:-/tmp/mds-`hostname`}
MDSSIZE=${MDSSIZE:-100000}
OSTDEV=${OSTDEV:-/tmp/ost-`hostname`}
OSTSIZE=${OSTSIZE:-100000}
MOUNT=${MOUNT:-/mnt/lustre}
MOUNT1=${MOUNT1:-${MOUNT}1}
MOUNT2=${MOUNT2:-${MOUNT}2}
UPCALL=${UPCALL:-$PWD/replay-single-upcall.sh}
FSTYPE=${FSTYPE:-ext3}
TIMEOUT=${TIMEOUT:-5}

start() {
    facet=$1
    shift
    lconf --node ${facet}_facet $@ replay-dual.xml
}

stop() {
    facet=$1
    shift
    lconf --node ${facet}_facet $@ --cleanup replay-dual.xml
}

replay_barrier() {
    local dev=$1
    sync
    lctl --device %${dev}1 readonly
    lctl --device %${dev}1 notransno
}

fail() {
    local facet=$1
    stop $facet --force --failover --nomod
    start $facet --nomod
    df $MOUNT1 | tail -1
    df $MOUNT2 | tail -1
}

do_lmc() {
    lmc -m replay-dual.xml $@
}

add_facet() {
    local facet=$1
    shift
    do_lmc --add node --node ${facet}_facet $@ --timeout $TIMEOUT
    do_lmc --add net --node ${facet}_facet --nid localhost --nettype tcp
}

gen_config() {
    rm -f replay-dual.xml
    add_facet mds
    add_facet ost
    add_facet client1 --lustre_upcall $UPCALL
    add_facet client2 --lustre_upcall $UPCALL
    do_lmc --add mds --node mds_facet --mds mds1 --dev $MDSDEV --size $MDSSIZE
    do_lmc --add ost --node ost_facet --ost ost1 --dev $OSTDEV --size $OSTSIZE
    do_lmc --add mtpt --node client1_facet --path $MOUNT1 --mds mds1 --ost ost1
    do_lmc --add mtpt --node client1_facet --path $MOUNT2 --mds mds1 --ost ost1
}
error() {
    echo '**** FAIL:' $@
    exit 1
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
        if [ ! -z "$ONLY" ]; then
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

EQUALS="======================================================================"

run_one() {
    testnum=$1
    message=$2
    
    # Pretty tests run faster.
    echo -n '=====' $testnum: $message
	local suffixlen=`echo -n $2 | awk '{print 65 - length($0)}'`
    printf ' %.*s\n' $suffixlen $EQUALS

    test_${testnum} || error "test_$testnum failed with $?"
}

build_test_filter

gen_config
start mds --reformat
start ost --reformat
start client1
start client2

test_1() {
    touch $MOUNT1/lustre-works
    replay_barrier mds
    touch $MOUNT2/lustre-does-not-work

    fail mds
    if [ -e $MOUNT1/lustre-does-not-work ]; then
        echo "$MOUNT1/lustre-does-not-work exists"
        exit 1
    fi
}

run_test 1 "|X| simple create"


test_2() {
    replay_barrier mds
    mkdir $MOUNT1/1

    fail mds
    ls $MOUNT2/1 
}

run_test 2 "|X| mkdir "


test_3() {
    replay_barrier mds
    mkdir $MOUNT1/1
    mkdir $MOUNT2/1/2

    fail mds
    ls $MOUNT2/1
    ls $MOUNT1/1/2 
}

run_test 3 "|X| mkdir 1, mkdir 1/2 "

stop client2
stop client1
stop ost
stop mds
