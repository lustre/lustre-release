#!/bin/bash

set -e
#set -v

#
# This test needs to be run on the client
#
SAVE_PWD=$PWD
LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
SETUP=${SETUP:-}
CLEANUP=${CLEANUP:-}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging
CHECK_GRANT=${CHECK_GRANT:-"yes"}
GRANT_CHECK_LIST=${GRANT_CHECK_LIST:-""}

require_dsh_mds || exit 0

# Skip these tests
# bug number:  17466 18857
ALWAYS_EXCEPT="61d   33a 33b    $REPLAY_SINGLE_EXCEPT"

#                                                  63 min  7 min  AT AT AT AT"
[ "$SLOW" = "no" ] && EXCEPT_SLOW="1 2 3 4 6 12 16 44a      44b    65 66 67 68"

build_test_filter

check_and_setup_lustre

mkdir -p $DIR

assert_DIR
rm -rf $DIR/[df][0-9]*

test_0a() {	# was test_0
    sleep 10
    mkdir $DIR/$tfile
    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
    rmdir $DIR/$tfile
}
run_test 0a "empty replay"

test_0b() {
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    # this test attempts to trigger a race in the precreation code,
    # and must run before any other objects are created on the filesystem
    fail ost1
    createmany -o $DIR/$tfile 20 || return 1
    unlinkmany $DIR/$tfile 20 || return 2
}
run_test 0b "ensure object created after recover exists. (3284)"

test_0d() {
    replay_barrier $SINGLEMDS
    umount $MOUNT
    facet_failover $SINGLEMDS
    zconf_mount `hostname` $MOUNT || error "mount fails"
    client_up || error "post-failover df failed"
}
run_test 0d "expired recovery with no clients"

test_1() {
    replay_barrier $SINGLEMDS
    mcreate $DIR/$tfile
    fail $SINGLEMDS
    $CHECKSTAT -t file $DIR/$tfile || return 1
    rm $DIR/$tfile
}
run_test 1 "simple create"

test_2a() {
    replay_barrier $SINGLEMDS
    touch $DIR/$tfile
    fail $SINGLEMDS
    $CHECKSTAT -t file $DIR/$tfile || return 1
    rm $DIR/$tfile
}
run_test 2a "touch"

test_2b() {
    mcreate $DIR/$tfile
    replay_barrier $SINGLEMDS
    touch $DIR/$tfile
    fail $SINGLEMDS
    $CHECKSTAT -t file $DIR/$tfile || return 1
    rm $DIR/$tfile
}
run_test 2b "touch"

test_3a() {
    local file=$DIR/$tfile
    replay_barrier $SINGLEMDS
    mcreate $file
    openfile -f O_DIRECTORY $file
    fail $SINGLEMDS
    $CHECKSTAT -t file $file || return 2
    rm $file
}
run_test 3a "replay failed open(O_DIRECTORY)"

test_3b() {
    replay_barrier $SINGLEMDS
#define OBD_FAIL_MDS_OPEN_PACK | OBD_FAIL_ONCE
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000114"
    touch $DIR/$tfile
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"
    fail $SINGLEMDS
    $CHECKSTAT -t file $DIR/$tfile && return 2
    return 0
}
run_test 3b "replay failed open -ENOMEM"

test_3c() {
    replay_barrier $SINGLEMDS
#define OBD_FAIL_MDS_ALLOC_OBDO | OBD_FAIL_ONCE
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000128"
    touch $DIR/$tfile
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"
    fail $SINGLEMDS

    $CHECKSTAT -t file $DIR/$tfile && return 2
    return 0
}
run_test 3c "replay failed open -ENOMEM"

test_4a() {	# was test_4
    replay_barrier $SINGLEMDS
    for i in `seq 10`; do
        echo "tag-$i" > $DIR/$tfile-$i
    done
    fail $SINGLEMDS
    for i in `seq 10`; do
      grep -q "tag-$i" $DIR/$tfile-$i || error "$tfile-$i"
    done
}
run_test 4a "|x| 10 open(O_CREAT)s"

test_4b() {
    replay_barrier $SINGLEMDS
    rm -rf $DIR/$tfile-*
    fail $SINGLEMDS
    $CHECKSTAT -t file $DIR/$tfile-* && return 1 || true
}
run_test 4b "|x| rm 10 files"

# The idea is to get past the first block of precreated files on both
# osts, and then replay.
test_5() {
    replay_barrier $SINGLEMDS
    for i in `seq 220`; do
        echo "tag-$i" > $DIR/$tfile-$i
    done
    fail $SINGLEMDS
    for i in `seq 220`; do
      grep -q "tag-$i" $DIR/$tfile-$i || error "$tfile-$i"
    done
    rm -rf $DIR/$tfile-*
    sleep 3
    # waiting for commitment of removal
}
run_test 5 "|x| 220 open(O_CREAT)"


test_6a() {	# was test_6
    mkdir -p $DIR/$tdir
    replay_barrier $SINGLEMDS
    mcreate $DIR/$tdir/$tfile
    fail $SINGLEMDS
    $CHECKSTAT -t dir $DIR/$tdir || return 1
    $CHECKSTAT -t file $DIR/$tdir/$tfile || return 2
    sleep 2
    # waiting for log process thread
}
run_test 6a "mkdir + contained create"

test_6b() {
    mkdir -p $DIR/$tdir
    replay_barrier $SINGLEMDS
    rm -rf $DIR/$tdir
    fail $SINGLEMDS
    $CHECKSTAT -t dir $DIR/$tdir && return 1 || true
}
run_test 6b "|X| rmdir"

test_7() {
    mkdir -p $DIR/$tdir
    replay_barrier $SINGLEMDS
    mcreate $DIR/$tdir/$tfile
    fail $SINGLEMDS
    $CHECKSTAT -t dir $DIR/$tdir || return 1
    $CHECKSTAT -t file $DIR/$tdir/$tfile || return 2
    rm -fr $DIR/$tdir
}
run_test 7 "mkdir |X| contained create"

test_8() {
    # make sure no side-effect from previous test.
    rm -f $DIR/$tfile
    replay_barrier $SINGLEMDS
    multiop_bg_pause $DIR/$tfile mo_c || return 4
    MULTIPID=$!
    fail $SINGLEMDS
    ls $DIR/$tfile
    $CHECKSTAT -t file $DIR/$tfile || return 1
    kill -USR1 $MULTIPID || return 2
    wait $MULTIPID || return 3
    rm $DIR/$tfile
}
run_test 8 "creat open |X| close"

test_9() {
    replay_barrier $SINGLEMDS
    mcreate $DIR/$tfile
    local old_inum=`ls -i $DIR/$tfile | awk '{print $1}'`
    fail $SINGLEMDS
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
    replay_barrier $SINGLEMDS
    mv $DIR/$tfile $DIR/$tfile-2
    rm -f $DIR/$tfile
    fail $SINGLEMDS
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
    replay_barrier $SINGLEMDS
    echo "new" > $DIR/$tfile
    grep new $DIR/$tfile
    grep old $DIR/$tfile-2
    fail $SINGLEMDS
    grep new $DIR/$tfile || return 1
    grep old $DIR/$tfile-2 || return 2
}
run_test 11 "create open write rename |X| create-old-name read"

test_12() {
    mcreate $DIR/$tfile
    multiop_bg_pause $DIR/$tfile o_tSc || return 3
    pid=$!
    rm -f $DIR/$tfile
    replay_barrier $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 1

    fail $SINGLEMDS
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 12 "open, unlink |X| close"


# 1777 - replay open after committed chmod that would make
#        a regular open a failure
test_13() {
    mcreate $DIR/$tfile
    multiop_bg_pause $DIR/$tfile O_wc || return 3
    pid=$!
    chmod 0 $DIR/$tfile
    $CHECKSTAT -p 0 $DIR/$tfile
    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 1

    $CHECKSTAT -s 1 -p 0 $DIR/$tfile || return 2
    rm $DIR/$tfile || return 4
    return 0
}
run_test 13 "open chmod 0 |x| write close"

test_14() {
    multiop_bg_pause $DIR/$tfile O_tSc || return 4
    pid=$!
    rm -f $DIR/$tfile
    replay_barrier $SINGLEMDS
    kill -USR1 $pid || return 1
    wait $pid || return 2

    fail $SINGLEMDS
    [ -e $DIR/$tfile ] && return 3
    return 0
}
run_test 14 "open(O_CREAT), unlink |X| close"

test_15() {
    multiop_bg_pause $DIR/$tfile O_tSc || return 5
    pid=$!
    rm -f $DIR/$tfile
    replay_barrier $SINGLEMDS
    touch $DIR/g11 || return 1
    kill -USR1 $pid
    wait $pid || return 2

    fail $SINGLEMDS
    [ -e $DIR/$tfile ] && return 3
    touch $DIR/h11 || return 4
    return 0
}
run_test 15 "open(O_CREAT), unlink |X|  touch new, close"


test_16() {
    replay_barrier $SINGLEMDS
    mcreate $DIR/$tfile
    munlink $DIR/$tfile
    mcreate $DIR/$tfile-2
    fail $SINGLEMDS
    [ -e $DIR/$tfile ] && return 1
    [ -e $DIR/$tfile-2 ] || return 2
    munlink $DIR/$tfile-2 || return 3
}
run_test 16 "|X| open(O_CREAT), unlink, touch new,  unlink new"

test_17() {
    replay_barrier $SINGLEMDS
    multiop_bg_pause $DIR/$tfile O_c || return 4
    pid=$!
    fail $SINGLEMDS
    kill -USR1 $pid || return 1
    wait $pid || return 2
    $CHECKSTAT -t file $DIR/$tfile || return 3
    rm $DIR/$tfile
}
run_test 17 "|X| open(O_CREAT), |replay| close"

test_18() {
    replay_barrier $SINGLEMDS
    multiop_bg_pause $DIR/$tfile O_tSc || return 8
    pid=$!
    rm -f $DIR/$tfile
    touch $DIR/$tfile-2 || return 1
    echo "pid: $pid will close"
    kill -USR1 $pid
    wait $pid || return 2

    fail $SINGLEMDS
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
    replay_barrier $SINGLEMDS
    mcreate $DIR/$tfile
    echo "old" > $DIR/$tfile
    mv $DIR/$tfile $DIR/$tfile-2
    grep old $DIR/$tfile-2
    fail $SINGLEMDS
    grep old $DIR/$tfile-2 || return 2
}
run_test 19 "|X| mcreate, open, write, rename "

test_20a() {	# was test_20
    replay_barrier $SINGLEMDS
    multiop_bg_pause $DIR/$tfile O_tSc || return 3
    pid=$!
    rm -f $DIR/$tfile

    fail $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 20a "|X| open(O_CREAT), unlink, replay, close (test mds_cleanup_orphans)"

test_20b() { # bug 10480
    BEFOREUSED=`df -P $DIR | tail -1 | awk '{ print $3 }'`

    dd if=/dev/zero of=$DIR/$tfile bs=4k count=10000 &
    pid=$!
    while [ ! -e $DIR/$tfile ] ; do
        usleep 60                           # give dd a chance to start
    done

    lfs getstripe $DIR/$tfile || return 1
    rm -f $DIR/$tfile || return 2       # make it an orphan
    mds_evict_client
    client_up || client_up || true    # reconnect

    fail $SINGLEMDS                            # start orphan recovery
    wait_recovery_complete $SINGLEMDS || error "MDS recovery not done"
    wait_mds_ost_sync || return 3
    AFTERUSED=`df -P $DIR | tail -1 | awk '{ print $3 }'`
    log "before $BEFOREUSED, after $AFTERUSED"
    [ $AFTERUSED -gt $((BEFOREUSED + 20)) ] && \
        error "after $AFTERUSED > before $BEFOREUSED"
    return 0
}
run_test 20b "write, unlink, eviction, replay, (test mds_cleanup_orphans)"

test_20c() { # bug 10480
    multiop_bg_pause $DIR/$tfile Ow_c || return 1
    pid=$!

    ls -la $DIR/$tfile

    mds_evict_client
    client_up || client_up || true    # reconnect

    kill -USR1 $pid
    wait $pid || return 1
    [ -s $DIR/$tfile ] || error "File was truncated"

    return 0
}
run_test 20c "check that client eviction does not affect file content"

test_21() {
    replay_barrier $SINGLEMDS
    multiop_bg_pause $DIR/$tfile O_tSc || return 5
    pid=$!
    rm -f $DIR/$tfile
    touch $DIR/g11 || return 1

    fail $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 2
    [ -e $DIR/$tfile ] && return 3
    touch $DIR/h11 || return 4
    return 0
}
run_test 21 "|X| open(O_CREAT), unlink touch new, replay, close (test mds_cleanup_orphans)"

test_22() {
    multiop_bg_pause $DIR/$tfile O_tSc || return 3
    pid=$!

    replay_barrier $SINGLEMDS
    rm -f $DIR/$tfile

    fail $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 22 "open(O_CREAT), |X| unlink, replay, close (test mds_cleanup_orphans)"

test_23() {
    multiop_bg_pause $DIR/$tfile O_tSc || return 5
    pid=$!

    replay_barrier $SINGLEMDS
    rm -f $DIR/$tfile
    touch $DIR/g11 || return 1

    fail $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 2
    [ -e $DIR/$tfile ] && return 3
    touch $DIR/h11 || return 4
    return 0
}
run_test 23 "open(O_CREAT), |X| unlink touch new, replay, close (test mds_cleanup_orphans)"

test_24() {
    multiop_bg_pause $DIR/$tfile O_tSc || return 3
    pid=$!

    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
    rm -f $DIR/$tfile
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 24 "open(O_CREAT), replay, unlink, close (test mds_cleanup_orphans)"

test_25() {
    multiop_bg_pause $DIR/$tfile O_tSc || return 3
    pid=$!
    rm -f $DIR/$tfile

    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 25 "open(O_CREAT), unlink, replay, close (test mds_cleanup_orphans)"

test_26() {
    replay_barrier $SINGLEMDS
    multiop_bg_pause $DIR/$tfile-1 O_tSc || return 5
    pid1=$!
    multiop_bg_pause $DIR/$tfile-2 O_tSc || return 6
    pid2=$!
    rm -f $DIR/$tfile-1
    rm -f $DIR/$tfile-2
    kill -USR1 $pid2
    wait $pid2 || return 1

    fail $SINGLEMDS
    kill -USR1 $pid1
    wait $pid1 || return 2
    [ -e $DIR/$tfile-1 ] && return 3
    [ -e $DIR/$tfile-2 ] && return 4
    return 0
}
run_test 26 "|X| open(O_CREAT), unlink two, close one, replay, close one (test mds_cleanup_orphans)"

test_27() {
    replay_barrier $SINGLEMDS
    multiop_bg_pause $DIR/$tfile-1 O_tSc || return 5
    pid1=$!
    multiop_bg_pause $DIR/$tfile-2 O_tSc || return 6
    pid2=$!
    rm -f $DIR/$tfile-1
    rm -f $DIR/$tfile-2

    fail $SINGLEMDS
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
    multiop_bg_pause $DIR/$tfile-1 O_tSc || return 5
    pid1=$!
    multiop_bg_pause $DIR/$tfile-2 O_tSc || return 6
    pid2=$!
    replay_barrier $SINGLEMDS
    rm -f $DIR/$tfile-1
    rm -f $DIR/$tfile-2
    kill -USR1 $pid2
    wait $pid2 || return 1

    fail $SINGLEMDS
    kill -USR1 $pid1
    wait $pid1 || return 2
    [ -e $DIR/$tfile-1 ] && return 3
    [ -e $DIR/$tfile-2 ] && return 4
    return 0
}
run_test 28 "open(O_CREAT), |X| unlink two, close one, replay, close one (test mds_cleanup_orphans)"

test_29() {
    multiop_bg_pause $DIR/$tfile-1 O_tSc || return 5
    pid1=$!
    multiop_bg_pause $DIR/$tfile-2 O_tSc || return 6
    pid2=$!
    replay_barrier $SINGLEMDS
    rm -f $DIR/$tfile-1
    rm -f $DIR/$tfile-2

    fail $SINGLEMDS
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
    multiop_bg_pause $DIR/$tfile-1 O_tSc || return 5
    pid1=$!
    multiop_bg_pause $DIR/$tfile-2 O_tSc || return 6
    pid2=$!
    rm -f $DIR/$tfile-1
    rm -f $DIR/$tfile-2

    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
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
    multiop_bg_pause $DIR/$tfile-1 O_tSc || return 5
    pid1=$!
    multiop_bg_pause $DIR/$tfile-2 O_tSc || return 6
    pid2=$!
    rm -f $DIR/$tfile-1

    replay_barrier $SINGLEMDS
    rm -f $DIR/$tfile-2
    fail $SINGLEMDS
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
    multiop_bg_pause $DIR/$tfile O_c || return 2
    pid1=$!
    multiop_bg_pause $DIR/$tfile O_c || return 3
    pid2=$!
    mds_evict_client
    client_up || client_up || return 1
    kill -USR1 $pid1
    kill -USR1 $pid2
    wait $pid1 || return 4
    wait $pid2 || return 5
    return 0
}
run_test 32 "close() notices client eviction; close() after client eviction"

test_33a() {
    createmany -o $DIR/$tfile-%d 10
    replay_barrier_nosync $SINGLEMDS
    fail_abort $SINGLEMDS
    # recreate shouldn't fail
    createmany -o $DIR/$tfile--%d 10 || return 1
    rm $DIR/$tfile-* -f
    return 0
}
run_test 33a "fid seq shouldn't be reused after abort recovery"

test_33b() {
    #define OBD_FAIL_SEQ_ALLOC                          0x1311
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x1311"

    createmany -o $DIR/$tfile-%d 10
    replay_barrier_nosync $SINGLEMDS
    fail_abort $SINGLEMDS
    # recreate shouldn't fail
    createmany -o $DIR/$tfile--%d 10 || return 1
    rm $DIR/$tfile-* -f
    return 0
}
run_test 33b "test fid seq allocation"

test_34() {
    multiop_bg_pause $DIR/$tfile O_c || return 2
    pid=$!
    rm -f $DIR/$tfile

    replay_barrier $SINGLEMDS
    fail_abort $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 3
    [ -e $DIR/$tfile ] && return 1
    sync
    return 0
}
run_test 34 "abort recovery before client does replay (test mds_cleanup_orphans)"

# bug 2278 - generate one orphan on OST, then destroy it during recovery from llog
test_35() {
    touch $DIR/$tfile

#define OBD_FAIL_MDS_REINT_NET_REP       0x119
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000119"
    rm -f $DIR/$tfile &
    sleep 1
    sync
    sleep 1
    # give a chance to remove from MDS
    fail_abort $SINGLEMDS
    $CHECKSTAT -t file $DIR/$tfile && return 1 || true
}
run_test 35 "test recovery from llog for unlink op"

# b=2432 resent cancel after replay uses wrong cookie,
# so don't resend cancels
test_36() {
    replay_barrier $SINGLEMDS
    touch $DIR/$tfile
    checkstat $DIR/$tfile
    facet_failover $SINGLEMDS
    cancel_lru_locks mdc
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
    multiop_bg_pause $DIR/$tfile dD_c || return 2
    pid=$!
    rmdir $DIR/$tfile

    replay_barrier $SINGLEMDS
    # clear the dmesg buffer so we only see errors from this recovery
    dmesg -c >/dev/null
    fail_abort $SINGLEMDS
    kill -USR1 $pid
    dmesg | grep  "mds_unlink_orphan.*error .* unlinking orphan" && return 1
    wait $pid || return 3
    sync
    return 0
}
start_full_debug_logging
run_test 37 "abort recovery before client does replay (test mds_cleanup_orphans for directories)"
stop_full_debug_logging

test_38() {
    createmany -o $DIR/$tfile-%d 800
    unlinkmany $DIR/$tfile-%d 0 400
    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
    unlinkmany $DIR/$tfile-%d 400 400
    sleep 2
    $CHECKSTAT -t file $DIR/$tfile-* && return 1 || true
}
run_test 38 "test recovery from unlink llog (test llog_gen_rec) "

test_39() { # bug 4176
    createmany -o $DIR/$tfile-%d 800
    replay_barrier $SINGLEMDS
    unlinkmany $DIR/$tfile-%d 0 400
    fail $SINGLEMDS
    unlinkmany $DIR/$tfile-%d 400 400
    sleep 2
    $CHECKSTAT -t file $DIR/$tfile-* && return 1 || true
}
run_test 39 "test recovery from unlink llog (test llog_gen_rec) "

count_ost_writes() {
    lctl get_param -n osc.*.stats | awk -vwrites=0 '/ost_write/ { writes += $2 } END { print writes; }'
}

#b=2477,2532
test_40(){
    $LCTL mark multiop $MOUNT/$tfile OS_c
    multiop $MOUNT/$tfile OS_c  &
    PID=$!
    writeme -s $MOUNT/${tfile}-2 &
    WRITE_PID=$!
    sleep 1
    facet_failover $SINGLEMDS
#define OBD_FAIL_MDS_CONNECT_NET         0x117
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000117"
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


#b=2814
# make sure that a read to one osc doesn't try to double-unlock its page just
# because another osc is invalid.  trigger_group_io used to mistakenly return
# an error if any oscs were invalid even after having successfully put rpcs
# on valid oscs.  This was fatal if the caller was ll_readpage who unlocked
# the page, guarnateeing that the unlock from the RPC completion would
# assert on trying to unlock the unlocked page.
test_41() {
    [ $OSTCOUNT -lt 2 ] && \
	skip_env "skipping test 41: we don't have a second OST to test with" && \
	return

    local f=$MOUNT/$tfile
    # make sure the start of the file is ost1
    lfs setstripe $f -s $((128 * 1024)) -i 0
    do_facet client dd if=/dev/zero of=$f bs=4k count=1 || return 3
    cancel_lru_locks osc
    # fail ost2 and read from ost1
    local mdtosc=$(get_mdtosc_proc_path $SINGLEMDS $ost2_svc)
    local osc2dev=$(do_facet $SINGLEMDS "lctl get_param -n devices" | \
        grep $mdtosc | awk '{print $1}')
    [ -z "$osc2dev" ] && echo "OST: $ost2_svc" && lctl get_param -n devices && return 4
    do_facet $SINGLEMDS $LCTL --device $osc2dev deactivate || return 1
    do_facet client dd if=$f of=/dev/null bs=4k count=1 || return 3
    do_facet $SINGLEMDS $LCTL --device $osc2dev activate || return 2
    return 0
}
run_test 41 "read from a valid osc while other oscs are invalid"

# test MDS recovery after ost failure
test_42() {
    blocks=`df -P $MOUNT | tail -n 1 | awk '{ print $2 }'`
    createmany -o $DIR/$tfile-%d 800
    replay_barrier ost1
    unlinkmany $DIR/$tfile-%d 0 400
    debugsave
    lctl set_param debug=-1
    facet_failover ost1

    # osc is evicted, fs is smaller (but only with failout OSTs (bug 7287)
    #blocks_after=`df -P $MOUNT | tail -n 1 | awk '{ print $2 }'`
    #[ $blocks_after -lt $blocks ] || return 1
    echo wait for MDS to timeout and recover
    sleep $((TIMEOUT * 2))
    debugrestore
    unlinkmany $DIR/$tfile-%d 400 400
    $CHECKSTAT -t file $DIR/$tfile-* && return 2 || true
}
run_test 42 "recovery after ost failure"

# timeout in MDS/OST recovery RPC will LBUG MDS
test_43() { # bug 2530
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    replay_barrier $SINGLEMDS

    # OBD_FAIL_OST_CREATE_NET 0x204
    do_facet ost1 "lctl set_param fail_loc=0x80000204"
    fail $SINGLEMDS
    sleep 10
    do_facet ost1 "lctl set_param fail_loc=0"

    return 0
}
run_test 43 "mds osc import failure during recovery; don't LBUG"

test_44a() { # was test_44
    local at_max_saved=0

    mdcdev=`lctl get_param -n devices | awk '/MDT0000-mdc-/ {print $1}'`
    [ "$mdcdev" ] || return 2
    [ $(echo $mdcdev | wc -w) -eq 1 ] || { echo $mdcdev=$mdcdev && return 3; }

    # adaptive timeouts slow this way down
    if at_is_enabled; then
        at_max_saved=$(at_max_get mds)
        at_max_set 40 mds
    fi

    for i in `seq 1 10`; do
        echo "$i of 10 ($(date +%s))"
        do_facet $SINGLEMDS "lctl get_param -n mdt.*.mdt.timeouts | grep service"
        #define OBD_FAIL_TGT_CONN_RACE     0x701
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000701"
        # lctl below may fail, it is valid case
        $LCTL --device $mdcdev recover
        df $MOUNT
    done
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"
    [ $at_max_saved -ne 0 ] && at_max_set $at_max_saved mds
    return 0
}
run_test 44a "race in target handle connect"

test_44b() {
    local mdcdev=`lctl get_param -n devices | awk '/MDT0000-mdc-/ {print $1}'`
    [ "$mdcdev" ] || return 2
    [ $(echo $mdcdev | wc -w) -eq 1 ] || { echo $mdcdev=$mdcdev && return 3; }

    for i in `seq 1 10`; do
        echo "$i of 10 ($(date +%s))"
        do_facet $SINGLEMDS "lctl get_param -n mdt.*.mdt.timeouts | grep service"
        #define OBD_FAIL_TGT_DELAY_RECONNECT 0x704
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000704"
        # lctl below may fail, it is valid case
        $LCTL --device $mdcdev recover
        df $MOUNT
    done
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"
    return 0
}
run_test 44b "race in target handle connect"

test_44c() {
    replay_barrier $SINGLEMDS
    createmany -m $DIR/$tfile-%d 100
#define OBD_FAIL_TGT_RCVG_FLAG 0x712
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000712"
    fail_abort $SINGLEMDS
    unlinkmany $DIR/$tfile-%d 100 && return 1
    fail $SINGLEMDS
    unlinkmany $DIR/$tfile-%d 100 && return 1
    return 0
}
run_test 44c "race in target handle connect"

# Handle failed close
test_45() {
    mdcdev=`lctl get_param -n devices | awk '/MDT0000-mdc-/ {print $1}'`
    [ "$mdcdev" ] || return 2
    [ $(echo $mdcdev | wc -w) -eq 1 ] || { echo $mdcdev=$mdcdev && return 3; }

    $LCTL --device $mdcdev recover || return 6 

    multiop_bg_pause $DIR/$tfile O_c || return 1
    pid=$!

    # This will cause the CLOSE to fail before even
    # allocating a reply buffer
    $LCTL --device $mdcdev deactivate || return 4

    # try the close
    kill -USR1 $pid
    wait $pid || return 1

    $LCTL --device $mdcdev activate || return 5
    sleep 1

    $CHECKSTAT -t file $DIR/$tfile || return 2
    return 0
}
run_test 45 "Handle failed close"

test_46() {
    dmesg -c >/dev/null
    drop_reply "touch $DIR/$tfile"
    fail $SINGLEMDS
    # ironically, the previous test, 45, will cause a real forced close,
    # so just look for one for this test
    dmesg | grep -i "force closing client file handle for $tfile" && return 1
    return 0
}
run_test 46 "Don't leak file handle after open resend (3325)"

test_47() { # bug 2824
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    # create some files to make sure precreate has been done on all
    # OSTs. (just in case this test is run independently)
    createmany -o $DIR/$tfile 20  || return 1

    # OBD_FAIL_OST_CREATE_NET 0x204
    fail ost1
    do_facet ost1 "lctl set_param fail_loc=0x80000204"
    client_up || return 2

    # let the MDS discover the OST failure, attempt to recover, fail
    # and recover again.
    sleep $((3 * TIMEOUT))

    # Without 2824, this createmany would hang
    createmany -o $DIR/$tfile 20 || return 3
    unlinkmany $DIR/$tfile 20 || return 4

    do_facet ost1 "lctl set_param fail_loc=0"
    return 0
}
run_test 47 "MDS->OSC failure during precreate cleanup (2824)"

test_48() {
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0
    [ "$OSTCOUNT" -lt "2" ] && skip_env "$OSTCOUNT < 2 OSTs -- skipping" && return

    replay_barrier $SINGLEMDS
    createmany -o $DIR/$tfile 20  || return 1
    # OBD_FAIL_OST_EROFS 0x216
    facet_failover $SINGLEMDS
    do_facet ost1 "lctl set_param fail_loc=0x80000216"
    client_up || return 2

    createmany -o $DIR/$tfile 20 20 || return 2
    unlinkmany $DIR/$tfile 40 || return 3
    return 0
}
run_test 48 "MDS->OSC failure during precreate cleanup (2824)"

test_50() {
    local mdtosc=$(get_mdtosc_proc_path $SINGLEMDS $ost1_svc) 
    local oscdev=$(do_facet $SINGLEMDS "lctl get_param -n devices" | \
        grep $mdtosc | awk '{print $1}')
    [ "$oscdev" ] || return 1
    do_facet $SINGLEMDS $LCTL --device $oscdev recover || return 2
    do_facet $SINGLEMDS $LCTL --device $oscdev recover || return 3
    # give the mds_lov_sync threads a chance to run
    sleep 5
}
run_test 50 "Double OSC recovery, don't LASSERT (3812)"

# b3764 timed out lock replay
test_52() {
    touch $DIR/$tfile
    cancel_lru_locks mdc

    multiop $DIR/$tfile s || return 1
    replay_barrier $SINGLEMDS
#define OBD_FAIL_LDLM_REPLY              0x30c
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000030c"
    fail $SINGLEMDS || return 2
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x0"

    $CHECKSTAT -t file $DIR/$tfile-* && return 3 || true
}
run_test 52 "time out lock replay (3764)"

# bug 3462 - simultaneous MDC requests
test_53a() {
        cancel_lru_locks mdc    # cleanup locks from former test cases
        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
        close_pid=$!
        # give multiop a change to open
        sleep 1

        #define OBD_FAIL_MDS_CLOSE_NET 0x115
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000115"
        kill -USR1 $close_pid
        cancel_lru_locks mdc    # force the close
        do_facet $SINGLEMDS "lctl set_param fail_loc=0"

        mcreate $DIR/${tdir}-2/f || return 1

        # close should still be here
        [ -d /proc/$close_pid ] || return 2

        replay_barrier_nodf $SINGLEMDS
        fail $SINGLEMDS
        wait $close_pid || return 3

        $CHECKSTAT -t file $DIR/${tdir}-1/f || return 4
        $CHECKSTAT -t file $DIR/${tdir}-2/f || return 5
        rm -rf $DIR/${tdir}-*
}
run_test 53a "|X| close request while two MDC requests in flight"

test_53b() {
        cancel_lru_locks mdc    # cleanup locks from former test cases
        rm -rf $DIR/${tdir}-1 $DIR/${tdir}-2

        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop_bg_pause $DIR/${tdir}-1/f O_c || return 6
        close_pid=$!

        #define OBD_FAIL_MDS_REINT_NET 0x107
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000107"
        mcreate $DIR/${tdir}-2/f &
        open_pid=$!
        sleep 1

        do_facet $SINGLEMDS "lctl set_param fail_loc=0"
        kill -USR1 $close_pid
        cancel_lru_locks mdc    # force the close
        wait $close_pid || return 1
        # open should still be here
        [ -d /proc/$open_pid ] || return 2

        replay_barrier_nodf $SINGLEMDS
        fail $SINGLEMDS
        wait $open_pid || return 3

        $CHECKSTAT -t file $DIR/${tdir}-1/f || return 4
        $CHECKSTAT -t file $DIR/${tdir}-2/f || return 5
        rm -rf $DIR/${tdir}-*
}
run_test 53b "|X| open request while two MDC requests in flight"

test_53c() {
        cancel_lru_locks mdc    # cleanup locks from former test cases
        rm -rf $DIR/${tdir}-1 $DIR/${tdir}-2

        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
        close_pid=$!

        #define OBD_FAIL_MDS_REINT_NET 0x107
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000107"
        mcreate $DIR/${tdir}-2/f &
        open_pid=$!
        sleep 1

        #define OBD_FAIL_MDS_CLOSE_NET 0x115
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000115"
        kill -USR1 $close_pid
        cancel_lru_locks mdc    # force the close

        #bz20647: make sure all pids are exists before failover
        [ -d /proc/$close_pid ] || error "close_pid doesn't exist"
        [ -d /proc/$open_pid ] || error "open_pid doesn't exists"
        replay_barrier_nodf $SINGLEMDS
        fail_nodf $SINGLEMDS
        wait $open_pid || return 1
        sleep 2
        # close should be gone
        [ -d /proc/$close_pid ] && return 2
        do_facet $SINGLEMDS "lctl set_param fail_loc=0"

        $CHECKSTAT -t file $DIR/${tdir}-1/f || return 3
        $CHECKSTAT -t file $DIR/${tdir}-2/f || return 4
        rm -rf $DIR/${tdir}-*
}
run_test 53c "|X| open request and close request while two MDC requests in flight"

test_53d() {
        cancel_lru_locks mdc    # cleanup locks from former test cases
        rm -rf $DIR/${tdir}-1 $DIR/${tdir}-2

        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
        close_pid=$!
        # give multiop a chance to open
        sleep 1

        #define OBD_FAIL_MDS_CLOSE_NET_REP 0x13b
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000013b"
        kill -USR1 $close_pid
        cancel_lru_locks mdc    # force the close
        do_facet $SINGLEMDS "lctl set_param fail_loc=0"
        mcreate $DIR/${tdir}-2/f || return 1

        # close should still be here
        [ -d /proc/$close_pid ] || return 2
        fail $SINGLEMDS
        wait $close_pid || return 3

        $CHECKSTAT -t file $DIR/${tdir}-1/f || return 4
        $CHECKSTAT -t file $DIR/${tdir}-2/f || return 5
        rm -rf $DIR/${tdir}-*
}
run_test 53d "|X| close reply while two MDC requests in flight"

test_53e() {
        cancel_lru_locks mdc    # cleanup locks from former test cases
        rm -rf $DIR/${tdir}-1 $DIR/${tdir}-2

        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
        close_pid=$!

        #define OBD_FAIL_MDS_REINT_NET_REP 0x119
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x119"
        mcreate $DIR/${tdir}-2/f &
        open_pid=$!
        sleep 1

        do_facet $SINGLEMDS "lctl set_param fail_loc=0"
        kill -USR1 $close_pid
        cancel_lru_locks mdc    # force the close
        wait $close_pid || return 1
        # open should still be here
        [ -d /proc/$open_pid ] || return 2

        replay_barrier_nodf $SINGLEMDS
        fail $SINGLEMDS
        wait $open_pid || return 3

        $CHECKSTAT -t file $DIR/${tdir}-1/f || return 4
        $CHECKSTAT -t file $DIR/${tdir}-2/f || return 5
        rm -rf $DIR/${tdir}-*
}
run_test 53e "|X| open reply while two MDC requests in flight"

test_53f() {
        cancel_lru_locks mdc    # cleanup locks from former test cases
        rm -rf $DIR/${tdir}-1 $DIR/${tdir}-2

        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
        close_pid=$!

        #define OBD_FAIL_MDS_REINT_NET_REP 0x119
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x119"
        mcreate $DIR/${tdir}-2/f &
        open_pid=$!
        sleep 1

        #define OBD_FAIL_MDS_CLOSE_NET_REP 0x13b
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000013b"
        kill -USR1 $close_pid
        cancel_lru_locks mdc    # force the close

        #bz20647: make sure all pids are exists before failover
        [ -d /proc/$close_pid ] || error "close_pid doesn't exist"
        [ -d /proc/$open_pid ] || error "open_pid doesn't exists"
        replay_barrier_nodf $SINGLEMDS
        fail_nodf $SINGLEMDS
        wait $open_pid || return 1
        sleep 2
        # close should be gone
        [ -d /proc/$close_pid ] && return 2
        do_facet $SINGLEMDS "lctl set_param fail_loc=0"

        $CHECKSTAT -t file $DIR/${tdir}-1/f || return 3
        $CHECKSTAT -t file $DIR/${tdir}-2/f || return 4
        rm -rf $DIR/${tdir}-*
}
run_test 53f "|X| open reply and close reply while two MDC requests in flight"

test_53g() {
        cancel_lru_locks mdc    # cleanup locks from former test cases
        rm -rf $DIR/${tdir}-1 $DIR/${tdir}-2

        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
        close_pid=$!

        #define OBD_FAIL_MDS_REINT_NET_REP 0x119
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x119"
        mcreate $DIR/${tdir}-2/f &
        open_pid=$!
        sleep 1

        #define OBD_FAIL_MDS_CLOSE_NET 0x115
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000115"
        kill -USR1 $close_pid
        cancel_lru_locks mdc    # force the close
        do_facet $SINGLEMDS "lctl set_param fail_loc=0"

        #bz20647: make sure all pids are exists before failover
        [ -d /proc/$close_pid ] || error "close_pid doesn't exist"
        [ -d /proc/$open_pid ] || error "open_pid doesn't exists"
        replay_barrier_nodf $SINGLEMDS
        fail_nodf $SINGLEMDS
        wait $open_pid || return 1
        sleep 2
        # close should be gone
        [ -d /proc/$close_pid ] && return 2

        $CHECKSTAT -t file $DIR/${tdir}-1/f || return 3
        $CHECKSTAT -t file $DIR/${tdir}-2/f || return 4
        rm -rf $DIR/${tdir}-*
}
run_test 53g "|X| drop open reply and close request while close and open are both in flight"

test_53h() {
        cancel_lru_locks mdc    # cleanup locks from former test cases
        rm -rf $DIR/${tdir}-1 $DIR/${tdir}-2

        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
        close_pid=$!

        #define OBD_FAIL_MDS_REINT_NET 0x107
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000107"
        mcreate $DIR/${tdir}-2/f &
        open_pid=$!
        sleep 1

        #define OBD_FAIL_MDS_CLOSE_NET_REP 0x13b
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000013b"
        kill -USR1 $close_pid
        cancel_lru_locks mdc    # force the close
        sleep 1

        #bz20647: make sure all pids are exists before failover
        [ -d /proc/$close_pid ] || error "close_pid doesn't exist"
        [ -d /proc/$open_pid ] || error "open_pid doesn't exists"
        replay_barrier_nodf $SINGLEMDS
        fail_nodf $SINGLEMDS
        wait $open_pid || return 1
        sleep 2
        # close should be gone
        [ -d /proc/$close_pid ] && return 2
        do_facet $SINGLEMDS "lctl set_param fail_loc=0"

        $CHECKSTAT -t file $DIR/${tdir}-1/f || return 3
        $CHECKSTAT -t file $DIR/${tdir}-2/f || return 4
        rm -rf $DIR/${tdir}-*
}
run_test 53h "|X| open request and close reply while two MDC requests in flight"

#b_cray 54 "|X| open request and close reply while two MDC requests in flight"

#b3761 ASSERTION(hash != 0) failed
test_55() {
# OBD_FAIL_MDS_OPEN_CREATE | OBD_FAIL_ONCE
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000012b"
    touch $DIR/$tfile &
    # give touch a chance to run
    sleep 5
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x0"
    rm $DIR/$tfile
    return 0
}
run_test 55 "let MDS_CHECK_RESENT return the original return code instead of 0"

#b3440 ASSERTION(rec->ur_fid2->id) failed
test_56() {
    ln -s foo $DIR/$tfile
    replay_barrier $SINGLEMDS
    #drop_reply "cat $DIR/$tfile"
    fail $SINGLEMDS
    sleep 10
}
run_test 56 "don't replay a symlink open request (3440)"

#recovery one mds-ost setattr from llog
test_57() {
#define OBD_FAIL_MDS_OST_SETATTR       0x12c
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000012c"
    touch $DIR/$tfile
    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
    sleep 1
    $CHECKSTAT -t file $DIR/$tfile || return 1
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x0"
    rm $DIR/$tfile
}
run_test 57 "test recovery from llog for setattr op"

#recovery many mds-ost setattr from llog
test_58a() {
    mkdir -p $DIR/$tdir
#define OBD_FAIL_MDS_OST_SETATTR       0x12c
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000012c"
    createmany -o $DIR/$tdir/$tfile-%d 2500
    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
    sleep 2
    $CHECKSTAT -t file $DIR/$tdir/$tfile-* >/dev/null || return 1
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x0"
    unlinkmany $DIR/$tdir/$tfile-%d 2500
    rmdir $DIR/$tdir
}
run_test 58a "test recovery from llog for setattr op (test llog_gen_rec)"

test_58b() {
    mount_client $MOUNT2
    mkdir -p $DIR/$tdir
    touch $DIR/$tdir/$tfile
    replay_barrier $SINGLEMDS
    setfattr -n trusted.foo -v bar $DIR/$tdir/$tfile
    fail $SINGLEMDS
    VAL=`getfattr --absolute-names --only-value -n trusted.foo $MOUNT2/$tdir/$tfile`
    [ x$VAL = x"bar" ] || return 1
    rm -f $DIR/$tdir/$tfile
    rmdir $DIR/$tdir
    zconf_umount `hostname` $MOUNT2
}
run_test 58b "test replay of setxattr op"

test_58c() { # bug 16570
        mount_client $MOUNT2
        mkdir -p $DIR/$tdir
        touch $DIR/$tdir/$tfile
        drop_request "setfattr -n trusted.foo -v bar $DIR/$tdir/$tfile" || \
                return 1
        VAL=`getfattr --absolute-names --only-value -n trusted.foo $MOUNT2/$tdir/$tfile`
        [ x$VAL = x"bar" ] || return 2
        drop_reint_reply "setfattr -n trusted.foo1 -v bar1 $DIR/$tdir/$tfile" || \
                return 3
        VAL=`getfattr --absolute-names --only-value -n trusted.foo1 $MOUNT2/$tdir/$tfile`
        [ x$VAL = x"bar1" ] || return 4
        rm -f $DIR/$tdir/$tfile
        rmdir $DIR/$tdir
        zconf_umount `hostname` $MOUNT2
}
run_test 58c "resend/reconstruct setxattr op"

# log_commit_thread vs filter_destroy race used to lead to import use after free
# bug 11658
test_59() {
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    mkdir -p $DIR/$tdir
    createmany -o $DIR/$tdir/$tfile-%d 200
    sync
    unlinkmany $DIR/$tdir/$tfile-%d 200
#define OBD_FAIL_PTLRPC_DELAY_RECOV       0x507
    do_facet ost1 "lctl set_param fail_loc=0x507"
    fail ost1
    fail $SINGLEMDS
    do_facet ost1 "lctl set_param fail_loc=0x0"
    sleep 20
    rmdir $DIR/$tdir
}
run_test 59 "test log_commit_thread vs filter_destroy race"

# race between add unlink llog vs cat log init in post_recovery (only for b1_6)
# bug 12086: should no oops and No ctxt error for this test
test_60() {
    mkdir -p $DIR/$tdir
    createmany -o $DIR/$tdir/$tfile-%d 200
    replay_barrier $SINGLEMDS
    unlinkmany $DIR/$tdir/$tfile-%d 0 100
    fail $SINGLEMDS
    unlinkmany $DIR/$tdir/$tfile-%d 100 100
    local no_ctxt=`dmesg | grep "No ctxt"`
    [ -z "$no_ctxt" ] || error "ctxt is not initialized in recovery"
}
run_test 60 "test llog post recovery init vs llog unlink"

#test race  llog recovery thread vs llog cleanup
test_61a() {	# was test_61
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    mkdir -p $DIR/$tdir
    createmany -o $DIR/$tdir/$tfile-%d 800
    replay_barrier ost1
#   OBD_FAIL_OST_LLOG_RECOVERY_TIMEOUT 0x221
    unlinkmany $DIR/$tdir/$tfile-%d 800
    set_nodes_failloc "$(osts_nodes)" 0x80000221
    facet_failover ost1
    sleep 10
    fail ost1
    sleep 30
    set_nodes_failloc "$(osts_nodes)" 0x0

    $CHECKSTAT -t file $DIR/$tdir/$tfile-* && return 1
    rmdir $DIR/$tdir
}
run_test 61a "test race llog recovery vs llog cleanup"

#test race  mds llog sync vs llog cleanup
test_61b() {
#   OBD_FAIL_MDS_LLOG_SYNC_TIMEOUT 0x13a
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000013a"
    facet_failover $SINGLEMDS
    sleep 10
    fail $SINGLEMDS
    do_facet client dd if=/dev/zero of=$DIR/$tfile bs=4k count=1 || return 1
}
run_test 61b "test race mds llog sync vs llog cleanup"

#test race  cancel cookie cb vs llog cleanup
test_61c() {
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

#   OBD_FAIL_OST_CANCEL_COOKIE_TIMEOUT 0x222
    touch $DIR/$tfile
    set_nodes_failloc "$(osts_nodes)" 0x80000222
    rm $DIR/$tfile
    sleep 10
    fail ost1
    set_nodes_failloc "$(osts_nodes)" 0x0
}
run_test 61c "test race mds llog sync vs llog cleanup"

test_61d() { # bug 16002 # bug 17466 # bug 22137
#   OBD_FAIL_OBD_LLOG_SETUP        0x605
    stop mgs
    do_facet mgs "lctl set_param fail_loc=0x80000605"
    start mgs $MGSDEV $MGS_MOUNT_OPTS && error "mgs start should have failed"
    do_facet mgs "lctl set_param fail_loc=0"
    start mgs $MGSDEV $MGS_MOUNT_OPTS || error "cannot restart mgs"
}
run_test 61d "error in llog_setup should cleanup the llog context correctly"

test_62() { # Bug 15756 - don't mis-drop resent replay
    mkdir -p $DIR/$tdir
    replay_barrier $SINGLEMDS
    createmany -o $DIR/$tdir/$tfile- 25
#define OBD_FAIL_TGT_REPLAY_DROP         0x707
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000707"
    fail $SINGLEMDS
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"
    unlinkmany $DIR/$tdir/$tfile- 25 || return 2
    return 0
}
run_test 62 "don't mis-drop resent replay"

#Adaptive Timeouts (bug 3055)
AT_MAX_SET=0

at_cleanup () {
    local var
    local facet
    local at_new

    echo "Cleaning up AT ..."
    if [ -n "$ATOLDBASE" ]; then
        local at_history=$($LCTL get_param -n at_history)
        do_facet $SINGLEMDS "lctl set_param at_history=$at_history" || true
        do_facet ost1 "lctl set_param at_history=$at_history" || true
    fi

    if [ $AT_MAX_SET -ne 0 ]; then
        for facet in mds client ost; do
            var=AT_MAX_SAVE_${facet}
            echo restore AT on $facet to saved value ${!var}
            at_max_set ${!var} $facet
            at_new=$(at_max_get $facet)
            echo Restored AT value on $facet $at_new
            [ $at_new -eq ${!var} ] || \
            error "$facet : AT value was not restored SAVED ${!var} NEW $at_new"
        done
    fi
}

at_start()
{
    local at_max_new=600

    # Save at_max original values
    local facet
    if [ $AT_MAX_SET -eq 0 ]; then
        # Suppose that all osts have the same at_max
        for facet in mds client ost; do
            eval AT_MAX_SAVE_${facet}=$(at_max_get $facet)
        done
    fi
    local at_max
    for facet in mds client ost; do
        at_max=$(at_max_get $facet)
        if [ $at_max -ne $at_max_new ]; then
            echo "AT value on $facet is $at_max, set it by force temporarily to $at_max_new"
            at_max_set $at_max_new $facet
            AT_MAX_SET=1
        fi
    done

    if [ -z "$ATOLDBASE" ]; then
	ATOLDBASE=$(do_facet $SINGLEMDS "lctl get_param -n at_history")
        # speed up the timebase so we can check decreasing AT
        do_facet $SINGLEMDS "lctl set_param at_history=8" || true
        do_facet ost1 "lctl set_param at_history=8" || true

	# sleep for a while to cool down, should be > 8s and also allow
	# at least one ping to be sent. simply use TIMEOUT to be safe.
	sleep $TIMEOUT
    fi
}

test_65a() #bug 3055
{
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    at_start || return 0
    $LCTL dk > /dev/null
    debugsave
    sysctl -w lnet.debug="+other"
    # Slow down a request to the current service time, this is critical
    # because previous tests may have caused this value to increase.
    REQ_DELAY=`lctl get_param -n mdc.${FSNAME}-MDT0000-mdc-*.timeouts |
               awk '/portal 12/ {print $5}'`
    REQ_DELAY=$((${REQ_DELAY} + ${REQ_DELAY} / 4 + 5))

    do_facet $SINGLEMDS lctl set_param fail_val=$((${REQ_DELAY} * 1000))
#define OBD_FAIL_PTLRPC_PAUSE_REQ        0x50a
    do_facet $SINGLEMDS $LCTL set_param fail_loc=0x8000050a
    createmany -o $DIR/$tfile 10 > /dev/null
    unlinkmany $DIR/$tfile 10 > /dev/null
    # check for log message
    $LCTL dk | grep "Early reply #" || error "No early reply"
    debugrestore
    # client should show REQ_DELAY estimates
    lctl get_param -n mdc.${FSNAME}-MDT0000-mdc-*.timeouts | grep portal
    sleep 9
    lctl get_param -n mdc.${FSNAME}-MDT0000-mdc-*.timeouts | grep portal
}
run_test 65a "AT: verify early replies"

test_65b() #bug 3055
{
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    at_start || return 0
    # turn on D_ADAPTTO
    debugsave
    sysctl -w lnet.debug="other trace"
    $LCTL dk > /dev/null
    # Slow down a request to the current service time, this is critical
    # because previous tests may have caused this value to increase.
    lfs setstripe $DIR/$tfile --index=0 --count=1
    multiop $DIR/$tfile Ow1yc
    REQ_DELAY=`lctl get_param -n osc.${FSNAME}-OST0000-osc-*.timeouts |
               awk '/portal 6/ {print $5}'`
    REQ_DELAY=$((${REQ_DELAY} + ${REQ_DELAY} / 4 + 5))

    do_facet ost1 lctl set_param fail_val=${REQ_DELAY}
#define OBD_FAIL_OST_BRW_PAUSE_PACK      0x224
    do_facet ost1 $LCTL set_param fail_loc=0x224

    rm -f $DIR/$tfile
    lfs setstripe $DIR/$tfile --index=0 --count=1
    # force some real bulk transfer
    multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c

    do_facet ost1 $LCTL set_param fail_loc=0
    # check for log message
    $LCTL dk | grep "Early reply #" || error "No early reply"
    debugrestore
    # client should show REQ_DELAY estimates
    lctl get_param -n osc.${FSNAME}-OST0000-osc-*.timeouts | grep portal
}
run_test 65b "AT: verify early replies on packed reply / bulk"

test_66a() #bug 3055
{
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    at_start || return 0
    lctl get_param -n mdc.${FSNAME}-MDT0000-mdc-*.timeouts | grep "portal 12"
    # adjust 5s at a time so no early reply is sent (within deadline)
    do_facet $SINGLEMDS "$LCTL set_param fail_val=5000"
#define OBD_FAIL_PTLRPC_PAUSE_REQ        0x50a
    do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x8000050a"
    createmany -o $DIR/$tfile 20 > /dev/null
    unlinkmany $DIR/$tfile 20 > /dev/null
    lctl get_param -n mdc.${FSNAME}-MDT0000-mdc-*.timeouts | grep "portal 12"
    do_facet $SINGLEMDS "$LCTL set_param fail_val=10000"
    do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x8000050a"
    createmany -o $DIR/$tfile 20 > /dev/null
    unlinkmany $DIR/$tfile 20 > /dev/null
    lctl get_param -n mdc.${FSNAME}-MDT0000-mdc-*.timeouts | grep "portal 12"
    do_facet $SINGLEMDS "$LCTL set_param fail_loc=0"
    sleep 9
    createmany -o $DIR/$tfile 20 > /dev/null
    unlinkmany $DIR/$tfile 20 > /dev/null
    lctl get_param -n mdc.${FSNAME}-MDT0000-mdc-*.timeouts | grep "portal 12"
    CUR=$(lctl get_param -n mdc.${FSNAME}-MDT0000-mdc-*.timeouts | awk '/portal 12/ {print $5}')
    WORST=$(lctl get_param -n mdc.${FSNAME}-MDT0000-mdc-*.timeouts | awk '/portal 12/ {print $7}')
    echo "Current MDT timeout $CUR, worst $WORST"
    [ $CUR -lt $WORST ] || error "Current $CUR should be less than worst $WORST"
}
run_test 66a "AT: verify MDT service time adjusts with no early replies"

test_66b() #bug 3055
{
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    at_start || return 0
    ORIG=$(lctl get_param -n mdc.${FSNAME}-*.timeouts | awk '/network/ {print $4}')
    $LCTL set_param fail_val=$(($ORIG + 5))
#define OBD_FAIL_PTLRPC_PAUSE_REP      0x50c
    $LCTL set_param fail_loc=0x50c
    ls $DIR/$tfile > /dev/null 2>&1
    $LCTL set_param fail_loc=0
    CUR=$(lctl get_param -n mdc.${FSNAME}-*.timeouts | awk '/network/ {print $4}')
    WORST=$(lctl get_param -n mdc.${FSNAME}-*.timeouts | awk '/network/ {print $6}')
    echo "network timeout orig $ORIG, cur $CUR, worst $WORST"
    [ $WORST -gt $ORIG ] || error "Worst $WORST should be worse than orig $ORIG"
}
run_test 66b "AT: verify net latency adjusts"

test_67a() #bug 3055
{
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    at_start || return 0
    CONN1=$(lctl get_param -n osc.*.stats | awk '/_connect/ {total+=$2} END {print total}')
    # sleeping threads may drive values above this
    do_facet ost1 "$LCTL set_param fail_val=400"
#define OBD_FAIL_PTLRPC_PAUSE_REQ    0x50a
    do_facet ost1 "$LCTL set_param fail_loc=0x50a"
    createmany -o $DIR/$tfile 20 > /dev/null
    unlinkmany $DIR/$tfile 20 > /dev/null
    do_facet ost1 "$LCTL set_param fail_loc=0"
    CONN2=$(lctl get_param -n osc.*.stats | awk '/_connect/ {total+=$2} END {print total}')
    ATTEMPTS=$(($CONN2 - $CONN1))
    echo "$ATTEMPTS osc reconnect attempts on gradual slow"
    [ $ATTEMPTS -gt 0 ] && error_ignore 13721 "AT should have prevented reconnect"
    return 0
}
run_test 67a "AT: verify slow request processing doesn't induce reconnects"

test_67b() #bug 3055
{
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    at_start || return 0
    CONN1=$(lctl get_param -n osc.*.stats | awk '/_connect/ {total+=$2} END {print total}')

    # exhaust precreations on ost1
    local OST=$(lfs osts | grep ^0": " | awk '{print $2}' | sed -e 's/_UUID$//')
    local mdtosc=$(get_mdtosc_proc_path mds $OST)
    local last_id=$(do_facet $SINGLEMDS lctl get_param -n \
        osc.$mdtosc.prealloc_last_id)
    local next_id=$(do_facet $SINGLEMDS lctl get_param -n \
        osc.$mdtosc.prealloc_next_id)

    mkdir -p $DIR/$tdir/${OST}
    lfs setstripe $DIR/$tdir/${OST} -o 0 -c 1 || error "setstripe"
    echo "Creating to objid $last_id on ost $OST..."
#define OBD_FAIL_OST_PAUSE_CREATE        0x223
    do_facet ost1 "$LCTL set_param fail_val=20000"
    do_facet ost1 "$LCTL set_param fail_loc=0x80000223"
    createmany -o $DIR/$tdir/${OST}/f $next_id $((last_id - next_id + 2))

    client_reconnect
    do_facet ost1 "lctl get_param -n ost.OSS.ost_create.timeouts"
    log "phase 2"
    CONN2=$(lctl get_param -n osc.*.stats | awk '/_connect/ {total+=$2} END {print total}')
    ATTEMPTS=$(($CONN2 - $CONN1))
    echo "$ATTEMPTS osc reconnect attempts on instant slow"
    # do it again; should not timeout
    do_facet ost1 "$LCTL set_param fail_loc=0x80000223"
    cp /etc/profile $DIR/$tfile || error "cp failed"
    do_facet ost1 "$LCTL set_param fail_loc=0"
    client_reconnect
    do_facet ost1 "lctl get_param -n ost.OSS.ost_create.timeouts"
    CONN3=$(lctl get_param -n osc.*.stats | awk '/_connect/ {total+=$2} END {print total}')
    ATTEMPTS=$(($CONN3 - $CONN2))
    echo "$ATTEMPTS osc reconnect attempts on 2nd slow"
    [ $ATTEMPTS -gt 0 ] && error "AT should have prevented reconnect"
    return 0
}
run_test 67b "AT: verify instant slowdown doesn't induce reconnects"

test_68 () #bug 13813
{
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    at_start || return 0
    local ldlm_enqueue_min=$(find /sys -name ldlm_enqueue_min)
    [ -z "$ldlm_enqueue_min" ] && skip "missing /sys/.../ldlm_enqueue_min" && return 0
    local ldlm_enqueue_min_r=$(do_facet ost1 "find /sys -name ldlm_enqueue_min")
    [ -z "$ldlm_enqueue_min_r" ] && skip "missing /sys/.../ldlm_enqueue_min in the ost1" && return 0
    local ENQ_MIN=$(cat $ldlm_enqueue_min)
    local ENQ_MIN_R=$(do_facet ost1 "cat $ldlm_enqueue_min_r")
    echo $TIMEOUT >> $ldlm_enqueue_min
    do_facet ost1 "echo $TIMEOUT >> $ldlm_enqueue_min_r"

    rm -rf $DIR/$tdir
    mkdir -p $DIR/$tdir
    lfs setstripe $DIR/$tdir --index=0 --count=1
#define OBD_FAIL_LDLM_PAUSE_CANCEL       0x312
    $LCTL set_param fail_val=$(($TIMEOUT - 1))
    $LCTL set_param fail_loc=0x80000312
    cp /etc/profile $DIR/$tdir/${tfile}_1 || error "1st cp failed $?"
    $LCTL set_param fail_val=$((TIMEOUT * 5 / 4))
    $LCTL set_param fail_loc=0x80000312
    cp /etc/profile $DIR/$tdir/${tfile}_2 || error "2nd cp failed $?"
    $LCTL set_param fail_loc=0

    echo $ENQ_MIN >> $ldlm_enqueue_min
    do_facet ost1 "echo $ENQ_MIN_R >> $ldlm_enqueue_min_r"
    rm -rf $DIR/$tdir
    return 0
}
run_test 68 "AT: verify slowing locks"

at_cleanup
# end of AT tests includes above lines


# start multi-client tests
test_70a () {
	[ -z "$CLIENTS" ] && \
		{ skip "Need two or more clients." && return; }
	[ $CLIENTCOUNT -lt 2 ] && \
		{ skip "Need two or more clients, have $CLIENTCOUNT" && return; }

	echo "mount clients $CLIENTS ..."
	zconf_mount_clients $CLIENTS $MOUNT

	local clients=${CLIENTS//,/ }
	echo "Write/read files on $DIR ; clients $CLIENTS ... "
	for CLIENT in $clients; do
		do_node $CLIENT dd bs=1M count=10 if=/dev/zero \
			of=$DIR/${tfile}_${CLIENT} 2>/dev/null || \
				error "dd failed on $CLIENT"
	done

	local prev_client=$(echo $clients | sed 's/^.* \(.\+\)$/\1/')
	for C in ${CLIENTS//,/ }; do
		do_node $prev_client dd if=$DIR/${tfile}_${C} of=/dev/null 2>/dev/null || \
			error "dd if=$DIR/${tfile}_${C} failed on $prev_client"
		prev_client=$C
	done
	
	ls $DIR
}
run_test 70a "check multi client t-f"

check_for_process () {
	local clients=$1
	shift
	local prog=$@

	killall_process $clients "$prog" -0
}

killall_process () {
	local clients=${1:-$(hostname)}
	local name=$2
	local signal=$3
	local rc=0

	do_nodes $clients "killall $signal $name"
}

test_70b () {
	local clients=${CLIENTS:-$HOSTNAME}

	zconf_mount_clients $clients $MOUNT
	
	local duration=300
	[ "$SLOW" = "no" ] && duration=60
	# set duration to 900 because it takes some time to boot node
	[ "$FAILURE_MODE" = HARD ] && duration=900

	local cmd="rundbench 1 -t $duration"
	local pid=""
	do_nodesv $clients "set -x; MISSING_DBENCH_OK=$MISSING_DBENCH_OK \
		PATH=:$PATH:$LUSTRE/utils:$LUSTRE/tests/:$DBENCH_LIB \
		DBENCH_LIB=$DBENCH_LIB TESTSUITE=$TESTSUITE TESTNAME=$TESTNAME \
		LCTL=$LCTL $cmd" &
	pid=$!
	log "Started rundbench load pid=$pid ..."

	# give rundbench a chance to start, bug 24118
	sleep 2
	local elapsed=0
	local num_failovers=0
	local start_ts=$(date +%s)
	while [ $elapsed -lt $duration ]; do
		if ! check_for_process $clients rundbench; then
			error_noexit "rundbench not found on some of $clients!"
			killall_process $clients dbench
			break
		fi
		sleep 1
		replay_barrier $SINGLEMDS
		sleep 1 # give clients a time to do operations
		# Increment the number of failovers
		num_failovers=$((num_failovers+1))
		log "$TESTNAME fail $SINGLEMDS $num_failovers times"
		fail $SINGLEMDS
		elapsed=$(($(date +%s) - start_ts))
	done

	wait $pid || error "rundbench load on $clients failed!"
}
run_test 70b "mds recovery; $CLIENTCOUNT clients"
# end multi-client tests

test_73a() {
    multiop_bg_pause $DIR/$tfile O_tSc || return 3
    pid=$!
    rm -f $DIR/$tfile

    replay_barrier $SINGLEMDS
#define OBD_FAIL_LDLM_ENQUEUE       0x302
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000302"
    fail $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 73a "open(O_CREAT), unlink, replay, reconnect before open replay , close"

test_73b() {
    multiop_bg_pause $DIR/$tfile O_tSc || return 3
    pid=$!
    rm -f $DIR/$tfile

    replay_barrier $SINGLEMDS
#define OBD_FAIL_LDLM_REPLY       0x30c
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000030c"
    fail $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 73b "open(O_CREAT), unlink, replay, reconnect at open_replay reply, close"

test_73c() {
    multiop_bg_pause $DIR/$tfile O_tSc || return 3
    pid=$!
    rm -f $DIR/$tfile

    replay_barrier $SINGLEMDS
#define OBD_FAIL_TGT_LAST_REPLAY       0x710
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000710"
    fail $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 73c "open(O_CREAT), unlink, replay, reconnect at last_replay, close"

# bug 18554
test_74() {
    local clients=${CLIENTS:-$HOSTNAME}

    stop ost1
    zconf_umount_clients $clients $MOUNT
    facet_failover $SINGLEMDS
    zconf_mount_clients $clients $MOUNT
    mount_facet ost1
    touch $DIR/$tfile || return 1
    rm $DIR/$tfile || return 2
    clients_up || error "client evicted: $?"
    return 0
}
run_test 74 "Ensure applications don't fail waiting for OST recovery"

test_80a() {
    [ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0

    mkdir -p $DIR/$tdir
    replay_barrier mds2
    $CHECKSTAT -t dir $DIR/$tdir || error "$CHECKSTAT -t dir $DIR/$tdir failed"
    rmdir $DIR/$tdir || error "rmdir $DIR/$tdir failed"
    fail mds2
    stat $DIR/$tdir 2&>/dev/null && error "$DIR/$tdir still exist after recovery!"
    return 0
}
run_test 80a "CMD: unlink cross-node dir (fail mds with inode)"

test_80b() {
    [ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0

    mkdir -p $DIR/$tdir
    replay_barrier $SINGLEMDS
    $CHECKSTAT -t dir $DIR/$tdir || error "$CHECKSTAT -t dir $DIR/$tdir failed"
    rmdir $DIR/$tdir || error "rmdir $DIR/$tdir failed"
    fail $SINGLEMDS
    stat $DIR/$tdir 2&>/dev/null && error "$DIR/$tdir still exist after recovery!"
    return 0
}
run_test 80b "CMD: unlink cross-node dir (fail mds with name)"

test_81a() {
    [ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0

    mkdir -p $DIR/$tdir
    createmany -o $DIR/$tdir/f 3000 || error "createmany failed"
    sleep 10
    $CHECKSTAT -t dir $DIR/$tdir || error "$CHECKSTAT -t dir failed"
    $CHECKSTAT -t file $DIR/$tdir/f1002 || error "$CHECKSTAT -t file failed"
    replay_barrier $SINGLEMDS
    rm $DIR/$tdir/f1002 || error "rm $DIR/$tdir/f1002 failed"
    fail $SINGLEMDS
    stat $DIR/$tdir/f1002
}
run_test 81a "CMD: unlink cross-node file (fail mds with name)"

test_82a() {
    [ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0

    local dir=$DIR/d82a
    replay_barrier mds2
    mkdir $dir || error "mkdir $dir failed"
    log "FAILOVER mds2"
    fail mds2
    stat $DIR
    $CHECKSTAT -t dir $dir || error "$CHECKSTAT -t dir $dir failed"
}
run_test 82a "CMD: mkdir cross-node dir (fail mds with inode)"

test_82b() {
    [ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0

    local dir=$DIR/d82b
    replay_barrier $SINGLEMDS
    mkdir $dir || error "mkdir $dir failed"
    log "FAILOVER mds1"
    fail $SINGLEMDS
    stat $DIR
    $CHECKSTAT -t dir $dir || error "$CHECKSTAT -t dir $dir failed"
}
run_test 82b "CMD: mkdir cross-node dir (fail mds with name)"

test_83a() {
    mkdir -p $DIR/$tdir
    createmany -o $DIR/$tdir/$tfile- 10 || return 1
#define OBD_FAIL_MDS_FAIL_LOV_LOG_ADD       0x140
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000140"
    unlinkmany $DIR/$tdir/$tfile- 10 || return 2
}
run_test 83a "fail log_add during unlink recovery"

test_83b() {
    mkdir -p $DIR/$tdir
    createmany -o $DIR/$tdir/$tfile- 10 || return 1
    replay_barrier $SINGLEMDS
    unlinkmany $DIR/$tdir/$tfile- 10 || return 2
#define OBD_FAIL_MDS_FAIL_LOV_LOG_ADD       0x140
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000140"
    fail $SINGLEMDS
}
run_test 83b "fail log_add during unlink recovery"

test_84a() {
#define OBD_FAIL_MDS_OPEN_WAIT_CREATE  0x144
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000144"
    createmany -o $DIR/$tfile- 1 &
    PID=$!
    mds_evict_client
    wait $PID
    client_up || client_up || true    # reconnect
}
run_test 84a "stale open during export disconnect"

test_85a() { #bug 16774
    lctl set_param -n ldlm.cancel_unused_locks_before_replay "1"

    for i in `seq 100`; do
        echo "tag-$i" > $DIR/$tfile-$i
        grep -q "tag-$i" $DIR/$tfile-$i || error "f2-$i"
    done

    lov_id=`lctl dl | grep "clilov"`
    addr=`echo $lov_id | awk '{print $4}' | awk -F '-' '{print $3}'`
    count=`lctl get_param -n ldlm.namespaces.*MDT0000*$addr.lock_unused_count`
    echo "before recovery: unused locks count = $count"

    fail $SINGLEMDS

    count2=`lctl get_param -n ldlm.namespaces.*MDT0000*$addr.lock_unused_count`
    echo "after recovery: unused locks count = $count2"

    if [ $count2 -ge $count ]; then
        error "unused locks are not canceled"
    fi
}
run_test 85a "check the cancellation of unused locks during recovery(IBITS)"

test_85b() { #bug 16774
    lctl set_param -n ldlm.cancel_unused_locks_before_replay "1"

    lfs setstripe -o 0 -c 1 $DIR

    for i in `seq 100`; do
        dd if=/dev/urandom of=$DIR/$tfile-$i bs=4096 count=32 >/dev/null 2>&1
    done

    cancel_lru_locks osc

    for i in `seq 100`; do
        dd if=$DIR/$tfile-$i of=/dev/null bs=4096 count=32 >/dev/null 2>&1
    done

    lov_id=`lctl dl | grep "clilov"`
    addr=`echo $lov_id | awk '{print $4}' | awk -F '-' '{print $3}'`
    count=`lctl get_param -n ldlm.namespaces.*OST0000*$addr.lock_unused_count`
    echo "before recovery: unused locks count = $count"

    fail ost1

    count2=`lctl get_param -n ldlm.namespaces.*OST0000*$addr.lock_unused_count`
    echo "after recovery: unused locks count = $count2"

    if [ $count2 -ge $count ]; then
        error "unused locks are not canceled"
    fi
}
run_test 85b "check the cancellation of unused locks during recovery(EXTENT)"

test_86() {
        local clients=${CLIENTS:-$HOSTNAME}

        zconf_umount_clients $clients $MOUNT
        do_facet $SINGLEMDS lctl set_param mdt.${FSNAME}-MDT*.exports.clear=0
        remount_facet $SINGLEMDS
        zconf_mount_clients $clients $MOUNT
}
run_test 86 "umount server after clear nid_stats should not hit LBUG"

test_87() {
    do_facet ost1 "lctl set_param -n obdfilter.${ost1_svc}.sync_journal 0"

    replay_barrier ost1
    lfs setstripe -i 0 -c 1 $DIR/$tfile
    dd if=/dev/urandom of=$DIR/$tfile bs=1024k count=8 || error "Cannot write"
    cksum=`md5sum $DIR/$tfile | awk '{print $1}'`
    cancel_lru_locks osc
    fail ost1
    dd if=$DIR/$tfile of=/dev/null bs=1024k count=8 || error "Cannot read"
    cksum2=`md5sum $DIR/$tfile | awk '{print $1}'`
    if [ $cksum != $cksum2 ] ; then
	error "New checksum $cksum2 does not match original $cksum"
    fi
}
run_test 87 "write replay"

test_87b() {
    do_facet ost1 "lctl set_param -n obdfilter.${ost1_svc}.sync_journal 0"

    replay_barrier ost1
    lfs setstripe -i 0 -c 1 $DIR/$tfile
    dd if=/dev/urandom of=$DIR/$tfile bs=1024k count=8 || error "Cannot write"
    sleep 1 # Give it a chance to flush dirty data
    echo TESTTEST | dd of=$DIR/$tfile bs=1 count=8 seek=64
    cksum=`md5sum $DIR/$tfile | awk '{print $1}'`
    cancel_lru_locks osc
    fail ost1
    dd if=$DIR/$tfile of=/dev/null bs=1024k count=8 || error "Cannot read"
    cksum2=`md5sum $DIR/$tfile | awk '{print $1}'`
    if [ $cksum != $cksum2 ] ; then
	error "New checksum $cksum2 does not match original $cksum"
    fi
}
run_test 87b "write replay with changed data (checksum resend)"

test_88() { #bug 17485
    mkdir -p $DIR/$tdir
    mkdir -p $TMP/$tdir

    lfs setstripe $DIR/$tdir -o 0 -c 1 || error "setstripe"

    replay_barrier ost1
    replay_barrier $SINGLEMDS

    # exhaust precreations on ost1
    local OST=$(lfs osts | grep ^0": " | awk '{print $2}' | sed -e 's/_UUID$//')
    local mdtosc=$(get_mdtosc_proc_path $SINGLEMDS $OST)
    local last_id=$(do_facet $SINGLEMDS lctl get_param -n osc.$mdtosc.prealloc_last_id)
    local next_id=$(do_facet $SINGLEMDS lctl get_param -n osc.$mdtosc.prealloc_next_id)
    echo "before test: last_id = $last_id, next_id = $next_id"

    echo "Creating to objid $last_id on ost $OST..."
    createmany -o $DIR/$tdir/f-%d $next_id $((last_id - next_id + 2))

    #create some files to use some uncommitted objids
    last_id=$(($last_id + 1))
    createmany -o $DIR/$tdir/f-%d $last_id 8

    last_id2=$(do_facet $SINGLEMDS lctl get_param -n osc.$mdtosc.prealloc_last_id)
    next_id2=$(do_facet $SINGLEMDS lctl get_param -n osc.$mdtosc.prealloc_next_id)
    echo "before recovery: last_id = $last_id2, next_id = $next_id2" 

    # if test uses shutdown_facet && reboot_facet instead of facet_failover ()
    # it has to take care about the affected facets, bug20407
    local affected_mds1=$(affected_facets mds1)
    local affected_ost1=$(affected_facets ost1)

    shutdown_facet $SINGLEMDS
    shutdown_facet ost1

    reboot_facet $SINGLEMDS
    change_active $affected_mds1
    wait_for_facet $affected_mds1
    mount_facets $affected_mds1 || error "Restart of mds failed"

    reboot_facet ost1
    change_active $affected_ost1
    wait_for_facet $affected_ost1
    mount_facets $affected_ost1 || error "Restart of ost1 failed"

    clients_up

    last_id2=$(do_facet $SINGLEMDS lctl get_param -n osc.$mdtosc.prealloc_last_id)
    next_id2=$(do_facet $SINGLEMDS lctl get_param -n osc.$mdtosc.prealloc_next_id)
    echo "after recovery: last_id = $last_id2, next_id = $next_id2" 

    # create new files, which should use new objids, and ensure the orphan 
    # cleanup phase for ost1 is completed at the same time
    for i in `seq 8`; do
        file_id=$(($last_id + 10 + $i))
        dd if=/dev/urandom of=$DIR/$tdir/f-$file_id bs=4096 count=128
    done

    # if the objids were not recreated, then "ls" will failed for -ENOENT
    ls -l $DIR/$tdir/* || error "can't get the status of precreated files"

    local file_id
    # write into previously created files
    for i in `seq 8`; do
        file_id=$(($last_id + $i))
        dd if=/dev/urandom of=$DIR/$tdir/f-$file_id bs=4096 count=128
        cp -f $DIR/$tdir/f-$file_id $TMP/$tdir/
    done

    # compare the content
    for i in `seq 8`; do
        file_id=$(($last_id + $i))
        cmp $TMP/$tdir/f-$file_id $DIR/$tdir/f-$file_id || error "the content" \
        "of file is modified!"
    done

    rm -fr $TMP/$tdir
}
run_test 88 "MDS should not assign same objid to different files "

test_89() {
        cancel_lru_locks osc
        mkdir -p $DIR/$tdir
        rm -f $DIR/$tdir/$tfile
        wait_mds_ost_sync
        wait_destroy_complete
        BLOCKS1=$(df -P $MOUNT | tail -n 1 | awk '{ print $3 }')
        lfs setstripe -i 0 -c 1 $DIR/$tdir/$tfile
        dd if=/dev/zero bs=1M count=10 of=$DIR/$tdir/$tfile
        sync
        stop ost1
        facet_failover $SINGLEMDS
        rm $DIR/$tdir/$tfile
        umount $MOUNT
        mount_facet ost1
        zconf_mount $(hostname) $MOUNT
        client_up || return 1
        wait_mds_ost_sync
        BLOCKS2=$(df -P $MOUNT | tail -n 1 | awk '{ print $3 }')
        [ "$BLOCKS1" == "$BLOCKS2" ] || error $((BLOCKS2 - BLOCKS1)) blocks leaked
}

run_test 89 "no disk space leak on late ost connection"

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
exit_status
