#!/bin/bash

set -e
#set -v

#
# This test needs to be run on the client
#

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}


# Skip these tests
# bug number: 2766 4176
ALWAYS_EXCEPT="0b  39   $REPLAY_SINGLE_EXCEPT"

gen_config() {
    rm -f $XMLCONFIG
    add_mds $SINGLEMDS --dev $MDSDEV --size $MDSSIZE
    if [ ! -z "$mdsfailover_HOST" ]; then
	 add_mdsfailover $SINGLEMDS --dev $MDSDEV --size $MDSSIZE
    fi
    
    add_lov lov1 $SINGLEMDS --stripe_sz $STRIPE_BYTES \
	--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
    add_ost ost --lov lov1 --dev `ostdevname 1` --size $OSTSIZE
    add_ost ost2 --lov lov1 --dev `ostdevname 2` --size $OSTSIZE
    add_client client $SINGLEMDS --lov lov1 --path $MOUNT
}

build_test_filter

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanupall"}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w lnet.debug=0 || true
    $CLEANUP
    exit 0
fi

setup() {
    [ "$REFORMAT" ] && formatall
    setupall
}

$SETUP

if [ "$ONLY" == "setup" ]; then
    exit 0
fi

mkdir -p $DIR

test_0() {
    sleep 10
    mkdir $DIR/$tfile
    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
    rmdir $DIR/$tfile
}
run_test 0 "empty replay"

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
    local file=`ls /proc/fs/lustre/seq/cli-srv-$mds-mdc-*/width` 
    echo $width > $file
}

seq_get_width()
{
    local mds=$1
    local file=`ls /proc/fs/lustre/seq/cli-srv-$mds-mdc-*/width` 
    cat $file
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
    ./mcreate $DIR/$tfile
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
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x80000114"
    touch $DIR/$tfile
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0"
    fail $SINGLEMDS
    $CHECKSTAT -t file $DIR/$tfile && return 2
    return 0
}
run_test 3b "replay failed open -ENOMEM"

test_3c() {
    replay_barrier $SINGLEMDS
#define OBD_FAIL_MDS_ALLOC_OBDO | OBD_FAIL_ONCE
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x80000128"
    touch $DIR/$tfile
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0"
    fail $SINGLEMDS

    $CHECKSTAT -t file $DIR/$tfile && return 2
    return 0
}
run_test 3c "replay failed open -ENOMEM"

test_4() {
    replay_barrier $SINGLEMDS
    for i in `seq 10`; do
        echo "tag-$i" > $DIR/$tfile-$i
    done 
    fail $SINGLEMDS
    for i in `seq 10`; do
      grep -q "tag-$i" $DIR/$tfile-$i || error "$tfile-$i"
    done 
}
run_test 4 "|x| 10 open(O_CREAT)s"

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


test_6() {
    replay_barrier $SINGLEMDS
    mkdir $DIR/$tdir
    mcreate $DIR/$tdir/$tfile
    fail $SINGLEMDS
    $CHECKSTAT -t dir $DIR/$tdir || return 1
    $CHECKSTAT -t file $DIR/$tdir/$tfile || return 2
    sleep 2
    # waiting for log process thread
}
run_test 6 "mkdir + contained create"

test_6b() {
    replay_barrier $SINGLEMDS
    rm -rf $DIR/$tdir
    fail $SINGLEMDS
    $CHECKSTAT -t dir $DIR/$tdir && return 1 || true 
}
run_test 6b "|X| rmdir"

test_7() {
    mkdir $DIR/$tdir
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
    multiop $DIR/$tfile mo_c &
    MULTIPID=$!
    sleep 1
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
    multiop $DIR/$tfile o_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1
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
    multiop $DIR/$tfile O_wc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $DIR/$tfile O_c &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    fail $SINGLEMDS
    kill -USR1 $pid || return 1
    wait $pid || return 2
    $CHECKSTAT -t file $DIR/$tfile || return 3
    rm $DIR/$tfile
}
run_test 17 "|X| open(O_CREAT), |replay| close"

test_18() {
    replay_barrier $SINGLEMDS
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
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

test_20() {
    replay_barrier $SINGLEMDS
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
    rm -f $DIR/$tfile

    fail $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 1
    [ -e $DIR/$tfile ] && return 2
    return 0
}
run_test 20 "|X| open(O_CREAT), unlink, replay, close (test mds_cleanup_orphans)"

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
    sleep 2

    AFTERUSED=`df -P $DIR | tail -1 | awk '{ print $3 }'`
    log "before $BEFOREUSED, after $AFTERUSED"
    [ $AFTERUSED -gt $((BEFOREUSED + 20)) ] && \
        error "after $AFTERUSED > before $BEFOREUSED" && return 5
    return 0
}
run_test 20b "write, unlink, eviction, replay, (test mds_cleanup_orphans)"

test_20c() { # bug 10480
    dd if=/dev/zero of=$DIR/$tfile bs=4k count=10000

    exec 100< $DIR/$tfile

    ls -la $DIR/$tfile

    mds_evict_client

    df -P $DIR || df -P $DIR || true    # reconnect

    exec 100<&-

    test -s $DIR/$tfile || error "File was truncated"

    return 0
}
run_test 20c "check that client eviction does not affect file content"

test_21() {
    replay_barrier $SINGLEMDS
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 

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
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 

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
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 

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
    multiop $DIR/$tfile O_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $DIR/$tfile-1 O_tSc &
    pid1=$!
    multiop $DIR/$tfile-2 O_tSc &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $DIR/$tfile O_c &
    pid1=$!
    multiop $DIR/$tfile O_c &
    pid2=$!
    # give multiop a chance to open
    sleep 1
    mds_evict_client
    df $MOUNT || sleep 1 && df $MOUNT || return 1
    kill -USR1 $pid1
    kill -USR1 $pid2
    sleep 1
    return 0
}
run_test 32 "close() notices client eviction; close() after client eviction"

# Abort recovery before client complete
test_33() {
    replay_barrier $SINGLEMDS
    createmany -o $DIR/$tfile-%d 100
    fail_abort $SINGLEMDS
    # this file should be gone, because the replay was aborted
    $CHECKSTAT -t file $DIR/$tfile-* && return 3 
    unlinkmany $DIR/$tfile-%d 0 100
    return 0
}
run_test 33 "abort recovery before client does replay"

# Stale FID sequence 
test_33a() {
    replay_barrier $SINGLEMDS
    createmany -o $DIR/$tfile-%d 10
    fail_abort $SINGLEMDS
    unlinkmany $DIR/$tfile-%d 0 10
    # recreate shouldn't fail
    createmany -o $DIR/$tfile-%d 10 || return 3
    unlinkmany $DIR/$tfile-%d 0 10
    return 0
}
run_test 33a "fid shouldn't be reused after abort recovery"

test_34() {
    multiop $DIR/$tfile O_c &
    pid=$!
    # give multiop a chance to open
    sleep 1 
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
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x80000119"
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
    multiop $DIR/$tfile dD_c &
    pid=$!
    # give multiop a chance to open
    sleep 1 
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
    awk -vwrites=0 '/ost_write/ { writes += $2 } END { print writes; }' $LPROC/osc/*/stats
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
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x80000117"
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
    local f=$MOUNT/$tfile
    # make sure the start of the file is ost1
    lfs setstripe $f $((128 * 1024)) 0 0 
    do_facet client dd if=/dev/zero of=$f bs=4k count=1 || return 3
    cancel_lru_locks osc
    # fail ost2 and read from ost1
    local osc2dev=`grep ${ost2_svc}-osc-MDT0000 $LPROC/devices | awk '{print $1}'`
    [ "$osc2dev" ] || return 4
    $LCTL --device $osc2dev deactivate || return 1
    do_facet client dd if=$f of=/dev/null bs=4k count=1 || return 3
    $LCTL --device $osc2dev activate || return 2
    return 0
}
run_test 41 "read from a valid osc while other oscs are invalid"

# test MDS recovery after ost failure
test_42() {
    blocks=`df -P $MOUNT | tail -n 1 | awk '{ print $2 }'`
    createmany -o $DIR/$tfile-%d 800
    replay_barrier ost1
    unlinkmany $DIR/$tfile-%d 0 400
    DEBUG42=`sysctl -n lnet.debug`
    sysctl -w lnet.debug=-1
    facet_failover ost1
    
    # osc is evicted, fs is smaller (but only with failout OSTs (bug 7287)
    #blocks_after=`df -P $MOUNT | tail -n 1 | awk '{ print $2 }'`
    #[ $blocks_after -lt $blocks ] || return 1
    echo wait for MDS to timeout and recover
    sleep $((TIMEOUT * 2))
    sysctl -w lnet.debug="$DEBUG42"
    unlinkmany $DIR/$tfile-%d 400 400
    $CHECKSTAT -t file $DIR/$tfile-* && return 2 || true
}
run_test 42 "recovery after ost failure"

# timeout in MDS/OST recovery RPC will LBUG MDS
test_43() { # bug 2530
    replay_barrier $SINGLEMDS

    # OBD_FAIL_OST_CREATE_NET 0x204
    do_facet ost1 "sysctl -w lustre.fail_loc=0x80000204"
    fail $SINGLEMDS
    sleep 10
    do_facet ost1 "sysctl -w lustre.fail_loc=0"

    return 0
}
run_test 43 "mds osc import failure during recovery; don't LBUG"

test_44() {
    mdcdev=`awk '/MDT0000-mdc-/ {print $1}' $LPROC/devices`
    [ "$mdcdev" ] || exit 2
    for i in `seq 1 10`; do
	#define OBD_FAIL_TGT_CONN_RACE     0x701
	do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x80000701"
	$LCTL --device $mdcdev recover
	df $MOUNT
    done
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0"
    return 0
}
run_test 44 "race in target handle connect"

test_44b() {
    mdcdev=`awk '/MDT0000-mdc-/ {print $1}' $LPROC/devices`
    [ "$mdcdev" ] || exit 2
    for i in `seq 1 10`; do
	#define OBD_FAIL_TGT_DELAY_RECONNECT 0x704
	do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x80000704"
	$LCTL --device $mdcdev recover
	df $MOUNT
    done
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0"
    return 0
}
run_test 44b "race in target handle connect"

# Handle failed close
test_45() {
    mdcdev=`awk '/MDT0000-mdc-/ {print $1}' $LPROC/devices`
    [ "$mdcdev" ] || exit 2
    $LCTL --device $mdcdev recover

    multiop $DIR/$tfile O_c &
    pid=$!
    sleep 1

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
    do_facet ost1 "sysctl -w lustre.fail_loc=0x80000204"
    df $MOUNT || return 2

    # let the MDS discover the OST failure, attempt to recover, fail
    # and recover again.  
    sleep $((3 * TIMEOUT))

    # Without 2824, this createmany would hang 
    createmany -o $DIR/$tfile 20 || return 3
    unlinkmany $DIR/$tfile 20 || return 4

    do_facet ost1 "sysctl -w lustre.fail_loc=0"
    return 0
}
run_test 47 "MDS->OSC failure during precreate cleanup (2824)"

test_48() {
    replay_barrier $SINGLEMDS
    createmany -o $DIR/$tfile 20  || return 1
    # OBD_FAIL_OST_EROFS 0x216
    fail $SINGLEMDS
    do_facet ost1 "sysctl -w lustre.fail_loc=0x80000216"
    df $MOUNT || return 2

    createmany -o $DIR/$tfile 20 20 || return 2
    unlinkmany $DIR/$tfile 40 || return 3

    do_facet ost1 "sysctl -w lustre.fail_loc=0"
    return 0
}
run_test 48 "MDS->OSC failure during precreate cleanup (2824)"

test_50() {
    local oscdev=`grep ${ost1_svc}-osc-MDT0000 $LPROC/devices | awk '{print $1}'`
    [ "$oscdev" ] || return 1
    $LCTL --device $oscdev recover &&  $LCTL --device $oscdev recover
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
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x8000030c"
    fail $SINGLEMDS || return 2
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x0"

    $CHECKSTAT -t file $DIR/$tfile-* && return 3 || true
}
run_test 52 "time out lock replay (3764)"

#b_cray 53 "|X| open request and close reply while two MDC requests in flight"
#b_cray 54 "|X| open request and close reply while two MDC requests in flight"

#b3761 ASSERTION(hash != 0) failed
test_55() {
# OBD_FAIL_MDS_OPEN_CREATE | OBD_FAIL_ONCE
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x8000012b"
    touch $DIR/$tfile &
    # give touch a chance to run
    sleep 5
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x0"
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
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x8000012c"
    touch $DIR/$tfile
    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
    sleep 1
    $CHECKSTAT -t file $DIR/$tfile || return 1
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x0"
    rm $DIR/$tfile
}
run_test 57 "test recovery from llog for setattr op"

#recovery many mds-ost setattr from llog
test_58() {
#define OBD_FAIL_MDS_OST_SETATTR       0x12c
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x8000012c"
    mkdir $DIR/$tdir
    createmany -o $DIR/$tdir/$tfile-%d 2500
    replay_barrier $SINGLEMDS
    fail $SINGLEMDS
    sleep 2
    $CHECKSTAT -t file $DIR/$tdir/$tfile-* || return 1
    do_facet $SINGLEMDS "sysctl -w lustre.fail_loc=0x0"
    unlinkmany $DIR/$tdir/$tfile-%d 2500
    rmdir $DIR/$tdir
}
run_test 58 "test recovery from llog for setattr op (test llog_gen_rec)"

# log_commit_thread vs filter_destroy race used to lead to import use after free
# bug 11658
test_59() {
    mkdir $DIR/$tdir
    createmany -o $DIR/$tdir/$tfile-%d 200
    sync
    unlinkmany $DIR/$tdir/$tfile-%d 200
#define OBD_FAIL_PTLRPC_DELAY_RECOV       0x507
    do_facet ost1 "sysctl -w lustre.fail_loc=0x507"
    fail ost1
    fail $SINGLEMDS
    do_facet ost1 "sysctl -w lustre.fail_loc=0x0"
    sleep 20
    rmdir $DIR/$tdir
}
run_test 59 "test log_commit_thread vs filter_destroy race"

# race between add unlink llog vs cat log init in post_recovery (only for b1_6)
# bug 12086: should no oops and No ctxt error for this test
test_60() {
    mkdir $DIR/$tdir
    createmany -o $DIR/$tdir/$tfile-%d 200
    replay_barrier $SINGLEMDS
    unlinkmany $DIR/$tdir/$tfile-%d 0 100
    fail $SINGLEMDS
    unlinkmany $DIR/$tdir/$tfile-%d 100 100
    local no_ctxt=`dmesg | grep "No ctxt"`
    [ -z "$no_ctxt" ] || error "ctxt is not initialized in recovery" 
}
run_test 60 "test llog post recovery init vs llog unlink"

equals_msg `basename $0`: test complete, cleaning up
$CLEANUP
