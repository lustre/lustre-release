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
CHECK_GRANT=${CHECK_GRANT:-"yes"}
GRANT_CHECK_LIST=${GRANT_CHECK_LIST:-""}


# Skip these tests
# bug number:
ALWAYS_EXCEPT="$REPLAY_SINGLE_EXCEPT"

#                                                  63 min  7 min  AT AT AT AT"
[ "$SLOW" = "no" ] && EXCEPT_SLOW="1 2 3 4 6 12 16 44a      44b    65 66 67 68"

build_test_filter

cleanup_and_setup_lustre

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
    # this test attempts to trigger a race in the precreation code,
    # and must run before any other objects are created on the filesystem
    fail ost1
    createmany -o $DIR/$tfile 20 || return 1
    unlinkmany $DIR/$tfile 20 || return 2
}
run_test 0b "ensure object created after recover exists. (3284)"

seq_set_width()
{
    local mds=$1
    local width=$2
    lctl set_param -n seq.cli-srv-$mds-mdc-*.width=$width
}

seq_get_width()
{
    local mds=$1
    lctl get_param -n seq.cli-srv-$mds-mdc-*.width
}

# This test should pass for single-mds and multi-mds configs.
# But for different configurations it tests different things.
#
# single-mds
# ----------
# (1) fld_create replay should happen;
#
# (2) fld_create replay should not return -EEXISTS, if it does
# this means sequence manager recovery code is buggy and allocated
# same sequence two times after recovery.
#
# multi-mds
# ---------
# (1) fld_create replay may not happen, because its home MDS is
# MDS2 which is not involved to revovery;
#
# (2) as fld_create does not happen on MDS1, it does not make any
# problem.
test_0c() {
    local label=`mdsdevlabel 1`
    [ -z "$label" ] && echo "No label for mds1" && return 1

    replay_barrier $SINGLEMDS
    local sw=`seq_get_width $label`

    # make seq manager switch to next sequence each
    # time as new fid is needed.
    seq_set_width $label 1

    # make sure that fld has created at least one new
    # entry on server
    touch $DIR/$tfile || return 2
    seq_set_width $label $sw

    # fail $SINGLEMDS and start recovery, replay RPCs, etc.
    fail $SINGLEMDS

    # wait for recovery finish
    sleep 10
    df $MOUNT

    # flush fld cache and dentry cache to make it lookup
    # created entry instead of revalidating existent one
    umount $MOUNT
    zconf_mount `hostname` $MOUNT

    # issue lookup which should call fld lookup which
    # should fail if client did not replay fld create
    # correctly and server has no fld entry
    touch $DIR/$tfile || return 3
    rm $DIR/$tfile || return 4
}
run_test 0c "fld create"

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
    replay_barrier $SINGLEMDS
    mcreate $DIR/$tfile
    o_directory $DIR/$tfile
    fail $SINGLEMDS
    $CHECKSTAT -t file $DIR/$tfile || return 2
    rm $DIR/$tfile
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
      grep -q "tag-$i" $DIR/$tfile-$i || error "f1c-$i"
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
    df -P $DIR || df -P $DIR || true    # reconnect

    fail $SINGLEMDS                            # start orphan recovery
    df -P $DIR || df -P $DIR || true    # reconnect
    wait_mds_recovery_done || error "MDS recovery not done"

    # FIXME just because recovery is done doesn't mean we've finished
    # orphan cleanup.  Fake it with a sleep for now...
    sleep 10
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

    df -P $DIR || df -P $DIR || true    # reconnect

    kill -USR1 $pid
    test -s $DIR/$tfile || error "File was truncated"

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
    df $MOUNT || sleep 1 && df $MOUNT || return 1
    kill -USR1 $pid1
    kill -USR1 $pid2
    sleep 1
    return 0
}
run_test 32 "close() notices client eviction; close() after client eviction"

# Abort recovery before client complete
test_33a() {	# was test_33
    replay_barrier $SINGLEMDS
    createmany -o $DIR/$tfile-%d 100
    fail_abort $SINGLEMDS
    # this file should be gone, because the replay was aborted
    $CHECKSTAT -t file $DIR/$tfile-* && return 3
    unlinkmany $DIR/$tfile-%d 0 100
    return 0
}
run_test 33a "abort recovery before client does replay"

# Stale FID sequence
test_33b() {	# was test_33a
    replay_barrier $SINGLEMDS
    createmany -o $DIR/$tfile-%d 10
    fail_abort $SINGLEMDS
    unlinkmany $DIR/$tfile-%d 0 10
    # recreate shouldn't fail
    createmany -o $DIR/$tfile-%d 10 || return 3
    unlinkmany $DIR/$tfile-%d 0 10
    return 0
}
run_test 33b "fid shouldn't be reused after abort recovery"

test_34() {
    multiop_bg_pause $DIR/$tfile O_c || return 2
    pid=$!
    rm -f $DIR/$tfile

    replay_barrier $SINGLEMDS
    fail_abort $SINGLEMDS
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
    sync
    return 0
}
run_test 37 "abort recovery before client does replay (test mds_cleanup_orphans for directories)"

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
	skip "skipping test 41: we don't have a second OST to test with" && \
	return

    local f=$MOUNT/$tfile
    # make sure the start of the file is ost1
    lfs setstripe $f -s $((128 * 1024)) -i 0
    do_facet client dd if=/dev/zero of=$f bs=4k count=1 || return 3
    cancel_lru_locks osc
    # fail ost2 and read from ost1
    local osc2dev=`do_facet mds "lctl get_param -n devices | grep ${ost2_svc}-osc-MDT0000" | awk '{print $1}'`
    [ -z "$osc2dev" ] && echo "OST: $ost2_svc" && lctl get_param -n devices && return 4
    do_facet mds $LCTL --device $osc2dev deactivate || return 1
    do_facet client dd if=$f of=/dev/null bs=4k count=1 || return 3
    do_facet mds $LCTL --device $osc2dev activate || return 2
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
    replay_barrier $SINGLEMDS

    # OBD_FAIL_OST_CREATE_NET 0x204
    do_facet ost1 "lctl set_param fail_loc=0x80000204"
    fail $SINGLEMDS
    sleep 10
    do_facet ost1 "lctl set_param fail_loc=0"

    return 0
}
run_test 43 "mds osc import failure during recovery; don't LBUG"

test_44a() {	# was test_44
    mdcdev=`lctl get_param -n devices | awk '/MDT0000-mdc-/ {print $1}'`
    [ "$mdcdev" ] || exit 2
    for i in `seq 1 10`; do
	#define OBD_FAIL_TGT_CONN_RACE     0x701
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000701"
	$LCTL --device $mdcdev recover
	df $MOUNT
    done
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"
    return 0
}
run_test 44a "race in target handle connect"

test_44b() {
    mdcdev=`lctl get_param -n devices | awk '/MDT0000-mdc-/ {print $1}'`
    [ "$mdcdev" ] || exit 2
    for i in `seq 1 10`; do
	#define OBD_FAIL_TGT_DELAY_RECONNECT 0x704
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000704"
	$LCTL --device $mdcdev recover
	df $MOUNT
    done
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"
    return 0
}
run_test 44b "race in target handle connect"

# Handle failed close
test_45() {
    mdcdev=`lctl get_param -n devices | awk '/MDT0000-mdc-/ {print $1}'`
    [ "$mdcdev" ] || exit 2
    $LCTL --device $mdcdev recover

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
    # create some files to make sure precreate has been done on all
    # OSTs. (just in case this test is run independently)
    createmany -o $DIR/$tfile 20  || return 1

    # OBD_FAIL_OST_CREATE_NET 0x204
    fail ost1
    do_facet ost1 "lctl set_param fail_loc=0x80000204"
    df $MOUNT || return 2

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
    replay_barrier $SINGLEMDS
    createmany -o $DIR/$tfile 20  || return 1
    # OBD_FAIL_OST_EROFS 0x216
    fail $SINGLEMDS
    do_facet ost1 "lctl set_param fail_loc=0x80000216"
    df $MOUNT || return 2

    createmany -o $DIR/$tfile 20 20 || return 2
    unlinkmany $DIR/$tfile 40 || return 3

    do_facet ost1 "lctl set_param fail_loc=0"
    return 0
}
run_test 48 "MDS->OSC failure during precreate cleanup (2824)"

test_50() {
    local oscdev=`do_facet $SINGLEMDS lctl get_param -n devices | grep ${ost1_svc}-osc-MDT0000 | awk '{print $1}'`
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
        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
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
        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
        close_pid=$!
        # give multiop a chance to open
        sleep 1

        #define OBD_FAIL_MDS_CLOSE_NET_REP 0x13f
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000013f"
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
        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
        close_pid=$!

        #define OBD_FAIL_MDS_REINT_NET_REP 0x119
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x119"
        mcreate $DIR/${tdir}-2/f &
        open_pid=$!
        sleep 1

        #define OBD_FAIL_MDS_CLOSE_NET_REP 0x13f
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000013f"
        kill -USR1 $close_pid
        cancel_lru_locks mdc    # force the close

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
        mkdir -p $DIR/${tdir}-1
        mkdir -p $DIR/${tdir}-2
        multiop $DIR/${tdir}-1/f O_c &
        close_pid=$!

        #define OBD_FAIL_MDS_REINT_NET 0x107
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000107"
        mcreate $DIR/${tdir}-2/f &
        open_pid=$!
        sleep 1

        #define OBD_FAIL_MDS_CLOSE_NET_REP 0x13f
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000013f"
        kill -USR1 $close_pid
        cancel_lru_locks mdc    # force the close
        sleep 1

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
test_58() {
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
run_test 58 "test recovery from llog for setattr op (test llog_gen_rec)"

# log_commit_thread vs filter_destroy race used to lead to import use after free
# bug 11658
test_59() {
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
    mkdir $DIR/$tdir
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
#   OBD_FAIL_MDS_LLOG_SYNC_TIMEOUT 0x140
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000140"
    facet_failover $SINGLEMDS 
    sleep 10
    fail $SINGLEMDS
    do_facet client dd if=/dev/zero of=$DIR/$tfile bs=4k count=1 || return 1
}
run_test 61b "test race mds llog sync vs llog cleanup"

#test race  cancel cookie cb vs llog cleanup
test_61c() {
#   OBD_FAIL_OST_CANCEL_COOKIE_TIMEOUT 0x222 
    touch $DIR/$tfile 
    set_nodes_failloc "$(osts_nodes)" 0x80000222
    rm $DIR/$tfile    
    sleep 10
    fail ost1
    set_nodes_failloc "$(osts_nodes)" 0x0
}
run_test 61c "test race mds llog sync vs llog cleanup"

# start multi-client tests
test_70a () {
	[ -z "$CLIENTS" ] && \
		{ skip "Need two or more clients." && return; }
	[ $CLIENTCOUNT -lt 2 ] && \
		{ skip "Need two or more clients, have $CLIENTCOUNT" && return; }

	echo "mount clients $CLIENTS ..."
	zconf_mount_clients $CLIENTS $DIR

	local clients=${CLIENTS//,/ }
	echo "Write/read files on $DIR ; clients $CLIENTS ... "
	for CLIENT in $clients; do
		do_node $CLIENT dd bs=1M count=10 if=/dev/zero \
			of=$DIR/${tfile}_${CLIENT} 2>/dev/null || \
				error "dd failed on $CLIENT"
	done

	local prev_client=$(echo $clients | sed 's/^.* \(\w\+\)$/\1/') 
	for C in ${CLIENTS//,/ }; do
		do_node $prev_client dd if=$DIR/${tfile}_${C} of=/dev/null 2>/dev/null || \
			error "dd if=$DIR/${tfile}_${C} failed on $prev_client"
		prev_client=$C
	done
	
	ls $DIR

	zconf_umount_clients $CLIENTS $DIR
}
run_test 70a "check multi client t-f"

test_70b () {
	[ -z "$CLIENTS" ] && \
		{ skip "Need two or more clients." && return; }
	[ $CLIENTCOUNT -lt 2 ] && \
		{ skip "Need two or more clients, have $CLIENTCOUNT" && return; }

	zconf_mount_clients $CLIENTS $DIR
	
	local duration="-t 60"
	local cmd="rundbench 1 $duration "
	local PID=""
	for CLIENT in ${CLIENTS//,/ }; do
		$PDSH $CLIENT "set -x; PATH=:$PATH:$LUSTRE/utils:$LUSTRE/tests/:${DBENCH_LIB} DBENCH_LIB=${DBENCH_LIB} $cmd" &
		PID=$!
		echo $PID >pid.$CLIENT
		echo "Started load PID=`cat pid.$CLIENT`"
	done

	replay_barrier $SINGLEMDS 
	sleep 3 # give clients a time to do operations

	log "$TESTNAME fail mds 1"
	fail $SINGLEMDS

# wait for client to reconnect to MDS
	sleep $TIMEOUT

	for CLIENT in ${CLIENTS//,/ }; do
		PID=`cat pid.$CLIENT`
		wait $PID
		rc=$?
		echo "load on ${CLIENT} returned $rc"
	done

	zconf_umount_clients $CLIENTS $DIR 
}
run_test 70b "mds recovery; $CLIENTCOUNT clients"
# end multi-client tests

equals_msg `basename $0`: test complete, cleaning up
check_and_cleanup_lustre
[ -f "$TESTSUITELOG" ] && cat $TESTSUITELOG || true
