#!/bin/sh

set -e

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
    lctl mark "REPLAY BARRIER"
}

fail() {
    local facet=$1
    lctl mark "FAIL $facet"
    stop $facet --force --failover --nomod
    start $facet --nomod
    lctl mark "RECOVER $facet"
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
    do_lmc --add mtpt --node client2_facet --path $MOUNT2 --mds mds1 --ost ost1
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
equals_msg() {
   msg="$@"

   local suffixlen=$((65 - ${#msg}))
   printf '===== %s %.*s\n' "$msg" $suffixlen $EQUALS
}

run_one() {
    testnum=$1
    message=$2
    
    # Pretty tests run faster.
    equals_msg $testnum: $message

    test_${testnum} || error "test_$testnum failed with $?"
}

build_test_filter

gen_config
start mds --reformat
start ost --reformat
start client1
start client2

test_1() {
    touch $MOUNT1/a
    replay_barrier mds
    touch $MOUNT2/b

    fail mds
    checkstat $MOUNT2/a || return 1
    checkstat $MOUNT1/b || return 2
    rm $MOUNT2/a $MOUNT1/b
    checkstat $MOUNT1/a && return 3
    checkstat $MOUNT2/b && return 4
    return 0
}

run_test 1 "|X| simple create"


test_2() {
    replay_barrier mds
    mkdir $MOUNT1/adir

    fail mds
    checkstat $MOUNT2/adir || return 1
    rmdir $MOUNT2/adir
    checkstat $MOUNT2/adir && return 2
    return 0
}

run_test 2 "|X| mkdir adir"

test_3() {
    replay_barrier mds
    mkdir $MOUNT1/adir
    mkdir $MOUNT2/adir/bdir

    fail mds
    checkstat $MOUNT2/adir      || return 1
    checkstat $MOUNT1/adir/bdir || return 2
    rmdir $MOUNT2/adir/bdir $MOUNT1/adir
    checkstat $MOUNT1/adir      && return 3
    checkstat $MOUNT2/adir/bdir && return 4
    return 0
}

run_test 3 "|X| mkdir adir, mkdir adir/bdir "

test_4() {
    mkdir $MOUNT1/adir
    replay_barrier mds
    mkdir $MOUNT1/adir  && return 1
    mkdir $MOUNT2/adir/bdir

    fail mds
    checkstat $MOUNT2/adir      || return 2
    checkstat $MOUNT1/adir/bdir || return 3

    rmdir $MOUNT2/adir/bdir $MOUNT1/adir
    checkstat $MOUNT1/adir      && return 4
    checkstat $MOUNT2/adir/bdir && return 5
    return 0
}

run_test 4 "|X| mkdir adir (-EEXIST), mkdir adir/bdir "


test_5() {
    # multiclient version of replay_single.sh/test_8
    mcreate $MOUNT1/a
    multiop $MOUNT2/a o_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $MOUNT1/a
    replay_barrier mds
    kill -USR1 $pid
    wait $pid || return 1

    fail mds
    [ -e $MOUNT2/a ] && return 2
    return 0
}
run_test 5 "open, unlink |X| close"


test_6() {
    mcreate $MOUNT1/a
    multiop $MOUNT2/a o_c &
    pid1=$!
    multiop $MOUNT1/a o_c &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $MOUNT1/a
    replay_barrier mds
    kill -USR1 $pid1
    wait $pid1 || return 1

    fail mds
    kill -USR1 $pid2
    wait $pid2 || return 1
    [ -e $MOUNT2/a ] && return 2
    return 0
}
run_test 6 "open1, open2, unlink |X| close1 [fail mds] close2"


equals_msg test complete, cleaning up
stop client2 --nomod
stop client1
stop ost
stop mds --dump cleanup-dual.log
