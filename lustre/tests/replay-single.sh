#!/bin/sh

set -e

# attempt to print a useful error location, but the ERR trap isn't
# exported to functions, and the $LINENO doesn't work in EXIT.

trap 'echo ERROR $0:$FUNCNAME:$LINENO: rc: $?' EXIT

LUSTRE=${LUSTRE:-`dirname $0`/..}
LTESTDIR=${LTESTDIR:-$LUSTRE/../ltest}
PATH=$PATH:$LUSTRE/utils:$LUSTRE/tests

RLUSTRE=${RLUSTRE:-$LUSTRE}
RPWD=${RPWD:-$PWD}

. $LTESTDIR/functional/llite/common/common.sh

CHECKSTAT="${CHECKSTAT:-checkstat} -v"

# XXX I wish all this stuff was in some default-config.sh somewhere
MOUNT=${MOUNT:-/mnt/lustre}
DIR=${DIR:-$MOUNT}
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
    lctl mark "REPLAY BARRIER"
}

fail() {
    local facet=$1
    stop $facet --force --failover --nomod
    start $facet --nomod
    df $MOUNT
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
    do_lmc --add mtpt --node client_facet --path $MOUNT --mds mds1 --ost ost1
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
start client $CLIENTLCONFARGS

mkdir -p $DIR

test_1() {
    replay_barrier mds
    mcreate $DIR/f1
    fail mds
    $CHECKSTAT -t file $DIR/f1 || error 
    rm $DIR/f1
}
run_test 1 "simple create"

test_1a() {
    replay_barrier mds
    touch $DIR/f1
    fail mds
    $CHECKSTAT -t file $DIR/f1 || error 
    rm $DIR/f1
}
run_test 1 "touch"

test_2() {
    replay_barrier mds
    mkdir $DIR/d2
    mcreate $DIR/d2/f2
    fail mds
    $CHECKSTAT -t dir $DIR/d2 || error 
    $CHECKSTAT -t file $DIR/d2/f2 || error 
    rm -fr $DIR/d2
}
run_test 2 "mkdir + contained create"

test_3() {
    mkdir $DIR/d3
    replay_barrier mds
    mcreate $DIR/d3/f3
    fail mds
    $CHECKSTAT -t dir $DIR/d3 || error 
    $CHECKSTAT -t file $DIR/d3/f3 || error 
    rm -fr $DIR/d3
}
run_test 3 "mkdir |X| contained create"

test_4() {
    replay_barrier mds
    multiop $DIR/f4 mo_c &
    MULTIPID=$!
    sleep 1
    fail mds
    ls $DIR/f4
    $CHECKSTAT -t file $DIR/f4 || error 
    kill -USR1 $MULTIPID
    wait
    rm $DIR/f4
}
run_test 4 "open |X| close"

test_5() {
    replay_barrier mds
    mcreate $DIR/f5
    local old_inum=`ls -i $DIR/f5 | awk '{print $1}'`
    fail mds
    local new_inum=`ls -i $DIR/f5 | awk '{print $1}'`

    echo " old_inum == $old_inum, new_inum == $new_inum"
    if [ $old_inum -eq $new_inum  ] ;
    then
        echo " old_inum and new_inum match"
    else
        echo "!!!! old_inum and new_inum NOT match"

    fi
    rm -f $DIR/f5
}
run_test 5 "|X| create (same inum/gen)"

test_6() {
    mcreate $DIR/f6
    replay_barrier mds
    mv $DIR/f6 $DIR/F6
    rm -f $DIR/F6
    fail mds
    $CHECKSTAT $DIR/f6 && return 1
    $CHECKSTAT $DIR/F6 && return 2
    return 0
}

run_test 6 "create |X| rename unlink"

test_7() {
    mcreate $DIR/f7
    echo "old" > $DIR/f7
    mv $DIR/f7 $DIR/F7
    replay_barrier mds
    mcreate $DIR/f7
    echo "new" > $DIR/f7
    cat $DIR/f7 | grep new 
    cat $DIR/F7 | grep old
    fail mds
    cat $DIR/f7 | grep new
    cat $DIR/F7 | grep old
}
run_test 7 "create open write rename |X| create-old-name read"

test_8() {
    mcreate $DIR/f8 
    multiop $DIR/f8 o_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/f8
    replay_barrier mds
    kill -USR1 $pid
    wait $pid || return 1

    fail mds
    [ -e $DIR/f8 ] && return 2
    return 0
}
run_test 8 "open, unlink |X| close"

# 1777 - replay open after committed chmod that would make
#        a regular open a failure    
test_9() {
    mcreate $DIR/f9 
    multiop $DIR/f9 O_wc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    chmod 0 $DIR/f9
    $CHECKSTAT -p 0 $DIR/f9
    replay_barrier mds
    fail mds
    kill -USR1 $pid
    wait $pid || return 1

    $CHECKSTAT -s 1 $DIR/f9
    return 0
}
run_test 9 "open chmod 0 |x| write close"


stop client $CLIENTLCONFARGS
stop ost
stop mds $MDSLCONFARGS --dump cleanup.log

trap - EXIT
