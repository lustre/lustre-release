#!/bin/sh

set -e

#
# This test needs to be run on the client
#

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

# Skip these tests
ALWAYS_EXCEPT=""


gen_config() {
    rm -f $XMLCONFIG
    add_mds mds --dev $MDSDEV --size $MDSSIZE
    if [ ! -z "$mdsfailover_HOST" ]; then
	 add_mdsfailover mds --dev $MDSDEV --size $MDSSIZE
    fi
    
    add_lov lov1 mds --stripe_sz $STRIPE_BYTES\
	--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
    add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE
    add_ost ost2 --lov lov1 --dev ${OSTDEV}-2 --size $OSTSIZE
    add_client client mds --lov lov1 --path $MOUNT
}

build_test_filter

cleanup() {
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activemds=`facet_active mds`
    if [ $activemds != "mds" ]; then
        fail mds
    fi
    zconf_umount `hostname` $MOUNT
    stop mds ${FORCE} $MDSLCONFARGS
    stop ost2 ${FORCE} --dump cleanup.log
    stop ost ${FORCE} --dump cleanup.log
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0 || true
    cleanup
    exit
fi

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

setup() {
    gen_config

    start ost --reformat $OSTLCONFARGS 
    start ost2 --reformat $OSTLCONFARGS 
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    start mds $MDSLCONFARGS --reformat
    zconf_mount `hostname` $MOUNT
    echo 0x3f0410 > /proc/sys/portals/debug
}

$SETUP

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
    sleep 3
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
    sync
    return 0
}
run_test 34 "abort recovery before client does replay (test mds_cleanup_orphans)"

# bug 2278 - generate one orphan on OST, then destroy it during recovery from llog 
test_35() {
    touch $DIR/$tfile

#define OBD_FAIL_MDS_REINT_NET_REP       0x119
    do_facet mds "sysctl -w lustre.fail_loc=0x80000119"
    rm -f $DIR/$tfile &
    sleep 1
    sync
    sleep 1
    # give a chance to remove from MDS
    fail_abort mds
    $CHECKSTAT -t file $DIR/$tfile && return 1 || true
}
run_test 35 "test recovery from llog for unlink op"

# b=2432 resent cancel after replay uses wrong cookie,
# so don't resend cancels
test_36() {
    replay_barrier mds
    touch $DIR/$tfile
    checkstat $DIR/$tfile
    facet_failover mds
    cancel_lru_locks MDC
    if dmesg | grep "unknown lock cookie"; then 
	echo "cancel after replay failed"
	return 1
    fi
}
run_test 36 "don't resend cancel"

# b=2368
# directory orphans can't be unlinked from PENDING directory
test_37() {
    rmdir $DIR/$tfile 2>/dev/null
    multiop $DIR/$tfile dD_c &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rmdir $DIR/$tfile

    replay_barrier mds
    # clear the dmesg buffer so we only see errors from this recovery
    dmesg -c >/dev/null
    fail_abort mds
    kill -USR1 $pid
    dmesg | grep  "mds_unlink_orphan.*error .* unlinking orphan" && return 1
    sync
    return 0
}
run_test 37 "abort recovery before client does replay (test mds_cleanup_orphans for directories)"

test_38() {
    createmany -o $DIR/$tfile-%d 800
    unlinkmany $DIR/$tfile-%d 0 400
    replay_barrier mds
    fail mds
    unlinkmany $DIR/$tfile-%d 400 400
    sleep 2
    $CHECKSTAT -t file $DIR/$tfile-* && return 1 || true
}
run_test 38 "test recovery from unlink llog (test llog_gen_rec) "

test_39() {
    createmany -o $DIR/$tfile-%d 800
    replay_barrier mds
    unlinkmany $DIR/$tfile-%d 0 400
    fail mds
    unlinkmany $DIR/$tfile-%d 400 400
    sleep 2
    $CHECKSTAT -t file $DIR/$tfile-* && return 1 || true
}
run_test 39 "test recovery from unlink llog (test llog_gen_rec) "

count_ost_writes() {
        cat /proc/fs/lustre/osc/*/stats |
            awk -vwrites=0 '/ost_write/ { writes += $2 } END { print writes; }'
}

#b=2477,2532
test_40(){
    $LCTL mark multiop $MOUNT/$tfile OS_c 
    multiop $MOUNT/$tfile OS_c  &
    PID=$!
    writeme -s $MOUNT/${tfile}-2 &
    WRITE_PID=$!
    sleep 1
    facet_failover mds
#define OBD_FAIL_MDS_CONNECT_NET         0x117
    do_facet mds "sysctl -w lustre.fail_loc=0x80000117"
    kill -USR1 $PID
    stat1=`count_ost_writes`
    sleep $TIMEOUT
    stat2=`count_ost_writes`
    echo "$stat1, $stat2"
    if [ $stat1 -lt $stat2 ]; then 
       echo "writes continuing during recovery"
       RC=0
    else
       echo "writes not continuing during recovery, bug 2477"
       RC=4
    fi
    echo "waiting for writeme $WRITE_PID"
    kill $WRITE_PID
    wait $WRITE_PID 

    echo "waiting for multiop $PID"
    wait $PID || return 2
    do_facet client munlink $MOUNT/$tfile  || return 3
    do_facet client munlink $MOUNT/${tfile}-2  || return 3
    return $RC
}
run_test 40 "cause recovery in ptlrpc, ensure IO continues"

equals_msg test complete, cleaning up
$CLEANUP

