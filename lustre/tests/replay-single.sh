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
MOUNTPT=${MOUNTPT:-/mnt/lustre}
MDSDEV=${MDSDEV:-/tmp/mds-`hostname`}
MDSSIZE=${MDSSIZE:-100000}
OSTDEV=${OSTDEV:-/tmp/ost-`hostname`}
OSTSIZE=${OSTSIZE:-100000}
UPCALL=${UPCALL:-$PWD/replay-single-upcall.sh}
FSTYPE=${FSTYPE:-ext3}
TIMEOUT=${TIMEOUT:-5}

start() {
    facet=$1
    shift
    lconf --node ${facet}_facet $@ replay-single.xml
}

stop() {
    facet=$1
    shift
    lconf --node ${facet}_facet $@ --cleanup replay-single.xml
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
    df $MOUNTPT
}

do_lmc() {
    lmc -m replay-single.xml $@
}

add_facet() {
    local facet=$1
    shift
    do_lmc --add node --node ${facet}_facet $@ --timeout $TIMEOUT
    do_lmc --add net --node ${facet}_facet --nid localhost --nettype tcp
}

gen_config() {
    rm -f replay-single.xml
    add_facet mds
    add_facet ost
    add_facet client --lustre_upcall $UPCALL
    do_lmc --add mds --node mds_facet --mds mds1 --dev $MDSDEV --size $MDSSIZE
    do_lmc --add ost --node ost_facet --ost ost1 --dev $OSTDEV --size $OSTSIZE
    do_lmc --add mtpt --node client_facet --path $MOUNTPT --mds mds1 --ost ost1
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
start mds --reformat $MDSLCONFARGS
start ost --reformat $OSTLCONFARGS
start client --gdb $CLIENTLCONFARGS

test_1() {
    replay_barrier mds
    mcreate $MOUNTPT/f1
    fail mds
    ls $MOUNTPT/f1
    rm $MOUNTPT/f1
}
run_test 1 "simple create"

test_2() {
    replay_barrier mds
    mkdir $MOUNTPT/d2
    mcreate $MOUNTPT/d2/f2
    fail mds
    ls $MOUNTPT/d2/f2
    rm -fr $MOUNTPT/d2
}
run_test 2 "mkdir + contained create"

test_3() {
    mkdir $MOUNTPT/d3
    replay_barrier mds
    mcreate $MOUNTPT/d3/f3
    fail mds
    ls $MOUNTPT/d3/f3
    rm -fr $MOUNTPT/d3
}
run_test 3 "mkdir |X| contained create"

test_4() {
    replay_barrier mds
    multiop $MOUNTPT/f4 mo_c &
    MULTIPID=$!
    sleep 1
    fail mds
    ls $MOUNTPT/f4
    kill -USR1 $MULTIPID
    wait
    rm $MOUNTPT/f4
}
run_test 4 "open |X| close"

test_5() {
    replay_barrier mds
    mcreate $MOUNTPT/f5
    local old_inum=`ls -i $MOUNTPT/f5 | awk '{print $1}'`
    fail mds
    local new_inum=`ls -i $MOUNTPT/f5 | awk '{print $1}'`

    echo " old_inum == $old_inum, new_inum == $new_inum"
    if [ $old_inum -eq $new_inum  ] ;
    then
        echo " old_inum and new_inum match"
    else
        echo "!!!! old_inum and new_inum NOT match"

    fi
    rm -f $MOUNTPT/f5
}
run_test 5 "|X| create (same inum/gen)"

test_6() {
    mcreate $MOUNTPT/f6
    replay_barrier mds
    mv $MOUNTPT/f6 $MOUNTPT/F6
    rm -f $MOUNTPT/F6
    fail mds
    ls $MOUNTPT/f6 
    ls $MOUNTPT/F6
    rm -f  $MOUNTPT/f6
    rm -f  $MOUNTPT/F6

}
run_test 6 "create |X| rename unlink"

test_7() {
    mcreate $MOUNTPT/f7
    echo "old" > $MOUNTPT/f7
    mv $MOUNTPT/f7 $MOUNTPT/F7
    replay_barrier mds
    mcreate $MOUNTPT/f7
    echo "new" > $MOUNTPT/f7
    cat $MOUNTPT/f7 | grep new 
    cat $MOUNTPT/F7 | grep old
    fail mds
    cat $MOUNTPT/f7 | grep new
    cat $MOUNTPT/F7 | grep old
}
run_test 7 "create open write rename |X| create-old-name read"

stop client $CLIENTLCONFARGS
stop ost
stop mds $MDSLCONFARGS

trap - EXIT
