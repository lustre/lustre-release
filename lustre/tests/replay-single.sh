#!/bin/sh

set -e

#
# This test needs to be run on the client
#

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env

# Skip these tests
ALWAYS_EXCEPT=""

# XXX I wish all this stuff was in some default-config.sh somewhere
mds_HOST=${mds_HOST:-`hostname`}
mdsfailover_HOST=${mdsfailover_HOST}
ost_HOST=${ost_HOST:-`hostname`}
client_HOST=${client_HOST:-`hostname`}

NETTYPE=${NETTYPE:-tcp}

PDSH=${PDSH:-no_dsh}

MOUNT=${MOUNT:-/mnt/lustre}
DIR=${DIR:-$MOUNT}
MDSDEV=${MDSDEV:-$ROOT/tmp/mds-`hostname`}
MDSFAILOVERDEV=${MDSFAILOVERDEV:-$MDSDEV}
MDSSIZE=${MDSSIZE:-10000}
OSTDEV=${OSTDEV:-$ROOT/tmp/ost-`hostname`}
OSTSIZE=${OSTSIZE:-10000}
UPCALL=${UPCALL:-$PWD/replay-single-upcall.sh}
FSTYPE=${FSTYPE:-ext3}
TIMEOUT=${TIMEOUT:-10}

STRIPE_BYTES=65536
STRIPES_PER_OBJ=0


gen_config() {
    rm -f $XMLCONFIG
    add_facet mds --timeout=${TIMEOUT}
    add_facet ost --timeout=${TIMEOUT}
    add_facet client --lustre_upcall $UPCALL --timeout=${TIMEOUT}
    do_lmc --add mds --node mds_facet --mds mds1 --dev $MDSDEV --size $MDSSIZE
    if [ ! -z "$mdsfailover_HOST" ]; then
	 add_facet mdsfailover
         do_lmc --add mds --failover --node mdsfailover_facet \
		--mds mds1 --dev $MDSFAILOVERDEV --size $MDSSIZE
    fi
    
    do_lmc --add lov --mds mds1 --lov lov1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
    do_lmc --add ost --lov lov1 --node ost_facet --ost ost1 --dev $OSTDEV --size $OSTSIZE
    do_lmc --add ost --lov lov1 --node ost_facet --ost ost2 --dev ${OSTDEV}-2 --size $OSTSIZE
    do_lmc --add mtpt --node client_facet --path $MOUNT --mds mds1 --ost lov1

#    do_lmc --add ost --node ost_facet --ost ost1 --dev $OSTDEV --size $OSTSIZE
#    do_lmc --add mtpt --node client_facet --path $MOUNT --mds mds1 --ost ost1
}

build_test_filter

cleanup() {
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activemds=`facet_active mds`
    if [ $activemds != "mds" ]; then
        fail mds
    fi
    zconf_umount $MOUNT
    stop mds ${FORCE} $MDSLCONFARGS
    stop ost ${FORCE} --dump cleanup.log
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0
    cleanup
    exit
fi

gen_config

start ost --reformat $OSTLCONFARGS 
[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
start mds $MDSLCONFARGS --reformat
zconf_mount $MOUNT

if [ "$ONLY" == "setup" ]; then
    exit 0
fi

mkdir -p $DIR

test_0() {
    replay_barrier mds
    fail mds
}
run_test 0 "empty replay"

test_1() {
    replay_barrier mds
    mcreate $DIR/$tfile
    fail mds
    $CHECKSTAT -t file $DIR/$tfile || return 1
    rm $DIR/$tfile
}
run_test 1 "simple create"

test_2a() {
    replay_barrier mds
    touch $DIR/$tfile
    fail mds
    $CHECKSTAT -t file $DIR/$tfile || return 1
    rm $DIR/$tfile
}
run_test 2a "touch"

test_2b() {
    ./mcreate $DIR/$tfile
    replay_barrier mds
    touch $DIR/$tfile
    fail mds
    $CHECKSTAT -t file $DIR/$tfile || return 1
    rm $DIR/$tfile
}
run_test 2b "touch"

test_3() {
    replay_barrier mds
    mcreate $DIR/$tfile
    o_directory $DIR/$tfile
    fail mds
    $CHECKSTAT -t file $DIR/$tfile || return 2
    rm $DIR/$tfile
}
run_test 3 "replay failed open"

test_4() {
    replay_barrier mds
    for i in `seq 10`; do
        echo "tag-$i" > $DIR/$tfile-$i
    done 
    fail mds
    for i in `seq 10`; do
      grep -q "tag-$i" $DIR/$tfile-$i || error "f1c-$i"
    done 
}
run_test 4 "|x| 10 open(O_CREAT)s"

test_4b() {
    replay_barrier mds
    rm -rf $DIR/$tfile-*
    fail mds
    $CHECKSTAT -t file $DIR/$tfile-* && return 1 || true
}
run_test 4b "|x| rm 10 files"

# The idea is to get past the first block of precreated files on both 
# osts, and then replay.
test_5() {
    replay_barrier mds
    for i in `seq 220`; do
        echo "tag-$i" > $DIR/$tfile-$i
    done 
    fail mds
    for i in `seq 220`; do
      grep -q "tag-$i" $DIR/$tfile-$i || error "f1c-$i"
    done 
    rm -rf $DIR/$tfile-*
    sleep 5
    # waiting for commitment of removal
}
run_test 5 "|x| 220 open(O_CREAT)"


test_6() {
    replay_barrier mds
    mkdir $DIR/$tdir
    mcreate $DIR/$tdir/$tfile
    fail mds
    $CHECKSTAT -t dir $DIR/$tdir || return 1
    $CHECKSTAT -t file $DIR/$tdir/$tfile || return 2
    sleep 2
    # waiting for log process thread
}
run_test 6 "mkdir + contained create"

test_6b() {
    replay_barrier mds
    rm -rf $DIR/$tdir
    fail mds
    $CHECKSTAT -t dir $DIR/$tdir && return 1 || true 
}
run_test 6b "|X| rmdir"

test_7() {
    mkdir $DIR/$tdir
    replay_barrier mds
    mcreate $DIR/$tdir/$tfile
    fail mds
    $CHECKSTAT -t dir $DIR/$tdir || return 1
    $CHECKSTAT -t file $DIR/$tdir/$tfile || return 2
    rm -fr $DIR/$tdir
}
run_test 7 "mkdir |X| contained create"

test_8() {
    replay_barrier mds
    multiop $DIR/$tfile mo_c &
    MULTIPID=$!
    sleep 1
    fail mds
    ls $DIR/$tfile
    $CHECKSTAT -t file $DIR/$tfile || return 1
    kill -USR1 $MULTIPID || return 2
    wait $MULTIPID || return 3
    rm $DIR/$tfile
}
run_test 8 "creat open |X| close"

test_9() {
    replay_barrier mds
    mcreate $DIR/$tfile
    local old_inum=`ls -i $DIR/$tfile | awk '{print $1}'`
    fail mds
    local new_inum=`ls -i $DIR/$tfile | awk '{print $1}'`

    echo " old_inum == $old_inum, new_inum == $new_inum"
    if [ $old_inum -eq $new_inum  ] ;
    then
        echo " old_inum and new_inum match"
    else
        echo "!!!! old_inum and new_inum NOT match"
        return 1
    fi
    rm $DIR/$tfile
}
run_test 9  "|X| create (same inum/gen)"

test_10() {
    mcreate $DIR/$tfile
    replay_barrier mds
    mv $DIR/$tfile $DIR/$tfile-2
    rm -f $DIR/$tfile
    fail mds
    $CHECKSTAT $DIR/$tfile && return 1
    $CHECKSTAT $DIR/$tfile-2 ||return 2
    rm $DIR/$tfile-2
    return 0
}
run_test 10 "create |X| rename unlink"

test_11() {
    mcreate $DIR/$tfile
    echo "old" > $DIR/$tfile
    mv $DIR/$tfile $DIR/$tfile-2
    replay_barrier mds
    echo "new" > $DIR/$tfile
    grep new $DIR/$tfile 
    grep old $DIR/$tfile-2
    fail mds
    grep new $DIR/$tfile || return 1
    grep old $DIR/$tfile-2 || return 2
}
run_test 11 "create open write rename |X| create-old-name read"

test_12() {
    mcreate $DIR/$tfile 
    multiop $DIR/$tfile o_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1
    rm -f $DIR/$tfile
    replay_barrier mds
    kill -USR1 $pid
    wait $pid || return 1

    fail mds
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 12 "open, unlink |X| close"


# 1777 - replay open after committed chmod that would make
#        a regular open a failure    
test_13() {
    mcreate $DIR/$tfile 
    multiop $DIR/$tfile O_wc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    chmod 0 $DIR/$tfile
    $CHECKSTAT -p 0 $DIR/$tfile
    replay_barrier mds
    fail mds
    kill -USR1 $pid
    wait $pid || return 1

    $CHECKSTAT -s 1 -p 0 $DIR/$tfile || return 2
    return 0
}
run_test 13 "open chmod 0 |x| write close"

test_14() {
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile
    replay_barrier mds
    kill -USR1 $pid || return 1
    wait $pid || return 2

    fail mds
    [ -e $DIR/$tfile ] && return 3
    return 0
}
run_test 14 "open(O_CREAT), unlink |X| close"

test_15() {
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile
    replay_barrier mds
    touch $DIR/g11 || return 1
    kill -USR1 $pid
    wait $pid || return 2

    fail mds
    [ -e $DIR/$tfile ] && return 3
    touch $DIR/h11 || return 4
    return 0
}
run_test 15 "open(O_CREAT), unlink |X|  touch new, close"


test_16() {
    replay_barrier mds
    mcreate $DIR/$tfile
    munlink $DIR/$tfile
    mcreate $DIR/$tfile-2
    fail mds
    [ -e $DIR/$tfile ] && return 1
    [ -e $DIR/$tfile-2 ] || return 2
    munlink $DIR/$tfile-2 || return 3
}
run_test 16 "|X| open(O_CREAT), unlink, touch new,  unlink new"

test_17() {
    replay_barrier mds
    multiop $DIR/$tfile O_c &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    fail mds
    kill -USR1 $pid || return 1
    wait $pid || return 2
    $CHECKSTAT -t file $DIR/$tfile || return 3
    rm $DIR/$tfile
}
run_test 17 "|X| open(O_CREAT), |replay| close"

test_18() {
    replay_barrier mds
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile
    touch $DIR/$tfile-2 || return 1
    kill -USR1 $pid
    wait $pid || return 2

    fail mds
    [ -e $DIR/$tfile ] && return 3
    [ -e $DIR/$tfile-2 ] || return 4
    # this touch frequently fails
    touch $DIR/$tfile-3 || return 5
    munlink $DIR/$tfile-2 || return 6
    munlink $DIR/$tfile-3 || return 7
    return 0
}
run_test 18 "|X| open(O_CREAT), unlink, touch new, close, touch, unlink"

# bug 1855 (a simpler form of test_11 above)
test_19() {
    replay_barrier mds
    mcreate $DIR/$tfile
    echo "old" > $DIR/$tfile
    mv $DIR/$tfile $DIR/$tfile-2
    grep old $DIR/$tfile-2
    fail mds
    grep old $DIR/$tfile-2 || return 2
}
run_test 19 "|X| mcreate, open, write, rename "

test_20() {
    replay_barrier mds
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile

    fail mds
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 20 "|X| open(O_CREAT), unlink, replay, close (test mds_cleanup_orphans)"

test_21() {
    replay_barrier mds
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile
    touch $DIR/g11 || return 1

    fail mds
    kill -USR1 $pid
    wait $pid || return 2
    [ -e $DIR/$tfile ] && return 3
    touch $DIR/h11 || return 4
    return 0
}
run_test 21 "|X| open(O_CREAT), unlink touch new, replay, close (test mds_cleanup_orphans)"

test_22() {
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 

    replay_barrier mds
    rm -f $DIR/$tfile

    fail mds
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 22 "open(O_CREAT), |X| unlink, replay, close (test mds_cleanup_orphans)"

test_23() {
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 

    replay_barrier mds
    rm -f $DIR/$tfile
    touch $DIR/g11 || return 1

    fail mds
    kill -USR1 $pid
    wait $pid || return 2
    [ -e $DIR/$tfile ] && return 3
    touch $DIR/h11 || return 4
    return 0
}
run_test 23 "open(O_CREAT), |X| unlink touch new, replay, close (test mds_cleanup_orphans)"

test_24() {
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 

    replay_barrier mds
    fail mds
    rm -f $DIR/$tfile
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 24 "open(O_CREAT), replay, unlink, close (test mds_cleanup_orphans)"

test_25() {
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile

    replay_barrier mds
    fail mds
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 25 "open(O_CREAT), unlink, replay, close (test mds_cleanup_orphans)"

test_26() {
    replay_barrier mds
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile-1
    rm -f $DIR/$tfile-2
    kill -USR1 $pid2
    wait $pid2 || return 1

    fail mds
    kill -USR1 $pid1
    wait $pid1 || return 2
    [ -e $DIR/$tfile-1 ] && return 3
    [ -e $DIR/$tfile-2 ] && return 4
    return 0
}
run_test 26 "|X| open(O_CREAT), unlink two, close one, replay, close one (test mds_cleanup_orphans)"

test_27() {
    replay_barrier mds
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile-1
    rm -f $DIR/$tfile-2

    fail mds
    kill -USR1 $pid1
    wait $pid1 || return 1
    kill -USR1 $pid2
    wait $pid2 || return 2
    [ -e $DIR/$tfile-1 ] && return 3
    [ -e $DIR/$tfile-2 ] && return 4
    return 0
}
run_test 27 "|X| open(O_CREAT), unlink two, replay, close two (test mds_cleanup_orphans)"

test_28() {
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
    replay_barrier mds
    rm -f $DIR/$tfile-1
    rm -f $DIR/$tfile-2
    kill -USR1 $pid2
    wait $pid2 || return 1

    fail mds
    kill -USR1 $pid1
    wait $pid1 || return 2
    [ -e $DIR/$tfile-1 ] && return 3
    [ -e $DIR/$tfile-2 ] && return 4
    return 0
}
run_test 28 "open(O_CREAT), |X| unlink two, close one, replay, close one (test mds_cleanup_orphans)"

test_29() {
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
    replay_barrier mds
    rm -f $DIR/$tfile-1
    rm -f $DIR/$tfile-2

    fail mds
    kill -USR1 $pid1
    wait $pid1 || return 1
    kill -USR1 $pid2
    wait $pid2 || return 2
    [ -e $DIR/$tfile-1 ] && return 3
    [ -e $DIR/$tfile-2 ] && return 4
    return 0
}
run_test 29 "open(O_CREAT), |X| unlink two, replay, close two (test mds_cleanup_orphans)"

test_30() {
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile-1
    rm -f $DIR/$tfile-2

    replay_barrier mds
    fail mds
    kill -USR1 $pid1
    wait $pid1 || return 1
    kill -USR1 $pid2
    wait $pid2 || return 2
    [ -e $DIR/$tfile-1 ] && return 3
    [ -e $DIR/$tfile-2 ] && return 4
    return 0
}
run_test 30 "open(O_CREAT) two, unlink two, replay, close two (test mds_cleanup_orphans)"

test_31() {
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile-1

    replay_barrier mds
    rm -f $DIR/$tfile-2
    fail mds
    kill -USR1 $pid1
    wait $pid1 || return 1
    kill -USR1 $pid2
    wait $pid2 || return 2
    [ -e $DIR/$tfile-1 ] && return 3
    [ -e $DIR/$tfile-2 ] && return 4
    return 0
}
run_test 31 "open(O_CREAT) two, unlink one, |X| unlink one, close two (test mds_cleanup_orphans)"

# tests for bug 2104; completion without crashing is success.  The close is
# stale, but we always return 0 for close, so the app never sees it.
test_32() {
    multiop $DIR/$tfile O_c &
    pid1=$!
    multiop $DIR/$tfile O_c &
    pid2=$!
    # give multiop a chance to open
    sleep 1
    mds_evict_client
    df $MOUNT || df $MOUNT || return 1
    kill -USR1 $pid1
    kill -USR1 $pid2
    sleep 1
    return 0
}
run_test 32 "close() notices client eviction; close() after client eviction"

# Abort recovery before client complete
test_33() {
    replay_barrier mds
    touch $DIR/$tfile
    fail_abort mds
    # this file should be gone, because the replay was aborted
    $CHECKSTAT -t file $DIR/$tfile && return 1
    return 0
}
run_test 33 "abort recovery before client does replay"

test_34() {
    multiop $DIR/$tfile O_c &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile

    replay_barrier mds
    fail_abort mds
    kill -USR1 $pid
    [ -e $DIR/$tfile ] && return 1
    sleep 5
    # wait for commitment of removal
    return 0
}
run_test 34 "abort recovery before client does replay (test mds_cleanup_orphans)"

equals_msg test complete, cleaning up
cleanup
