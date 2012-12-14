#!/bin/bash

set -e

# bug number:  10124
ALWAYS_EXCEPT="15c   $REPLAY_DUAL_EXCEPT"

LFS=${LFS:-lfs}
SETSTRIPE=${SETSTRIPE:-"$LFS setstripe"}
GETSTRIPE=${GETSTRIPE:-"$LFS getstripe"}
SAVE_PWD=$PWD
PTLDEBUG=${PTLDEBUG:--1}
LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}
MOUNT_2=${MOUNT_2:-"yes"}
. $LUSTRE/tests/test-framework.sh

init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

remote_mds_nodsh && skip "remote MDS with nodsh" && exit 0

[ "$SLOW" = "no" ] && EXCEPT_SLOW="21b"

build_test_filter

check_and_setup_lustre
MOUNTED=$(mounted_lustre_filesystems)
if ! $(echo $MOUNTED' ' | grep -w -q $MOUNT2' '); then
    zconf_mount $HOSTNAME $MOUNT2
    MOUNTED2=yes
fi

assert_DIR
rm -rf $DIR/[df][0-9]*

[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE

test_0a() {
    touch $MOUNT2/$tfile-A # force sync FLD/SEQ update before barrier
    replay_barrier $SINGLEMDS
#define OBD_FAIL_PTLRPC_FINISH_REPLAY | OBD_FAIL_ONCE
    touch $MOUNT2/$tfile
    createmany -o $MOUNT1/$tfile- 50
    $LCTL set_param fail_loc=0x80000514
    facet_failover $SINGLEMDS
    client_up || return 1
    umount -f $MOUNT2
    client_up || return 1
    zconf_mount `hostname` $MOUNT2 || error "mount2 fais"
    unlinkmany $MOUNT1/$tfile- 50 || return 2
    rm $MOUNT2/$tfile || return 3
    rm $MOUNT2/$tfile-A || return 4
}
run_test 0a "expired recovery with lost client"

test_0b() {
    replay_barrier $SINGLEMDS
    touch $MOUNT2/$tfile
    touch $MOUNT1/$tfile-2
    umount $MOUNT2
    facet_failover $SINGLEMDS
    umount -f $MOUNT1
    zconf_mount `hostname` $MOUNT1 || error "mount1 fais"
    zconf_mount `hostname` $MOUNT2 || error "mount2 fais"
    checkstat $MOUNT1/$tfile-2 && return 1
    checkstat $MOUNT2/$tfile && return 2
    return 0
}
run_test 0b "lost client during waiting for next transno"

test_1() {
    touch $MOUNT1/a
    replay_barrier $SINGLEMDS
    touch $MOUNT2/b

    fail $SINGLEMDS
    checkstat $MOUNT2/a || return 1
    checkstat $MOUNT1/b || return 2
    rm $MOUNT2/a $MOUNT1/b
    checkstat $MOUNT1/a && return 3
    checkstat $MOUNT2/b && return 4
    return 0
}

run_test 1 "|X| simple create"


test_2() {
    replay_barrier $SINGLEMDS
    mkdir $MOUNT1/adir

    fail $SINGLEMDS
    checkstat $MOUNT2/adir || return 1
    rmdir $MOUNT2/adir
    checkstat $MOUNT2/adir && return 2
    return 0
}
run_test 2 "|X| mkdir adir"

test_3() {
    replay_barrier $SINGLEMDS
    mkdir $MOUNT1/adir
    mkdir $MOUNT2/adir/bdir

    fail $SINGLEMDS
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
    replay_barrier $SINGLEMDS
    mkdir $MOUNT1/adir  && return 1
    mkdir $MOUNT2/adir/bdir

    fail $SINGLEMDS
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
    multiop_bg_pause $MOUNT2/a o_tSc || return  1
    pid=$!
    rm -f $MOUNT1/a
    replay_barrier $SINGLEMDS
    kill -USR1 $pid
    wait $pid || return 1

    fail $SINGLEMDS
    [ -e $MOUNT2/a ] && return 2
    return 0
}
run_test 5 "open, unlink |X| close"


test_6() {
    mcreate $MOUNT1/a
    multiop_bg_pause $MOUNT2/a o_c || return 1
    pid1=$!
    multiop_bg_pause $MOUNT1/a o_c || return 1
    pid2=$!
    rm -f $MOUNT1/a
    replay_barrier $SINGLEMDS
    kill -USR1 $pid1
    wait $pid1 || return 1

    fail $SINGLEMDS
    kill -USR1 $pid2
    wait $pid2 || return 1
    [ -e $MOUNT2/a ] && return 2
    return 0
}
run_test 6 "open1, open2, unlink |X| close1 [fail $SINGLEMDS] close2"

test_8() {
    replay_barrier $SINGLEMDS
    drop_reint_reply "mcreate $MOUNT1/$tfile"    || return 1
    fail $SINGLEMDS
    checkstat $MOUNT2/$tfile || return 2
    rm $MOUNT1/$tfile || return 3

    return 0
}
run_test 8 "replay of resent request"

test_9() {
    replay_barrier $SINGLEMDS
    mcreate $MOUNT1/$tfile-1
    mcreate $MOUNT2/$tfile-2
    # drop first reint reply
    do_facet $SINGLEMDS lctl set_param fail_loc=0x80000119
    fail $SINGLEMDS
    do_facet $SINGLEMDS lctl set_param fail_loc=0

    rm $MOUNT1/$tfile-[1,2] || return 1

    return 0
}
run_test 9 "resending a replayed create"

test_10() {
    mcreate $MOUNT1/$tfile-1
    replay_barrier $SINGLEMDS
    munlink $MOUNT1/$tfile-1
    mcreate $MOUNT2/$tfile-2
    # drop first reint reply
    do_facet $SINGLEMDS lctl set_param fail_loc=0x80000119
    fail $SINGLEMDS
    do_facet $SINGLEMDS lctl set_param fail_loc=0

    checkstat $MOUNT1/$tfile-1 && return 1
    checkstat $MOUNT1/$tfile-2 || return 2
    rm $MOUNT1/$tfile-2

    return 0
}
run_test 10 "resending a replayed unlink"

test_11() {
    replay_barrier $SINGLEMDS
    mcreate $MOUNT1/$tfile-1
    mcreate $MOUNT2/$tfile-2
    mcreate $MOUNT1/$tfile-3
    mcreate $MOUNT2/$tfile-4
    mcreate $MOUNT1/$tfile-5
    # drop all reint replies for a while
    do_facet $SINGLEMDS lctl set_param fail_loc=0x0119
    # note that with this fail_loc set, facet_failover df will fail
    facet_failover $SINGLEMDS
    #sleep for while, let both clients reconnect and timeout
    sleep $((TIMEOUT * 2))
    do_facet $SINGLEMDS lctl set_param fail_loc=0

    rm $MOUNT1/$tfile-[1-5] || return 1

    return 0
}
run_test 11 "both clients timeout during replay"

test_12() {
    replay_barrier $SINGLEMDS

    multiop_bg_pause $DIR/$tfile mo_c || return 1
    MULTIPID=$!

#define OBD_FAIL_LDLM_ENQUEUE            0x302
    do_facet $SINGLEMDS lctl set_param fail_loc=0x80000302
    facet_failover $SINGLEMDS
    do_facet $SINGLEMDS lctl set_param fail_loc=0
    clients_up || return 1

    ls $DIR/$tfile
    kill -USR1 $MULTIPID || return 3
    wait $MULTIPID || return 4
    $CHECKSTAT -t file $DIR/$tfile || return 2
    rm $DIR/$tfile

    return 0
}
run_test 12 "open resend timeout"

test_13() {
    multiop_bg_pause $DIR/$tfile mo_c || return 1
    MULTIPID=$!

    replay_barrier $SINGLEMDS

    kill -USR1 $MULTIPID || return 3
    wait $MULTIPID || return 4

    # drop close
    do_facet $SINGLEMDS lctl set_param fail_loc=0x80000115
    facet_failover $SINGLEMDS
    do_facet $SINGLEMDS lctl set_param fail_loc=0
    clients_up || return 1

    ls $DIR/$tfile
    $CHECKSTAT -t file $DIR/$tfile || return 2
    rm $DIR/$tfile

    return 0
}
run_test 13 "close resend timeout"

# test 14a removed after 18143 because it shouldn't fail anymore and do the same
# as test_15a

test_14b() {
    wait_mds_ost_sync
    wait_delete_completed
    BEFOREUSED=`df -P $DIR | tail -1 | awk '{ print $3 }'`
    mkdir -p $MOUNT1/$tdir
    $SETSTRIPE -o 0 $MOUNT1/$tdir
    replay_barrier $SINGLEMDS
    createmany -o $MOUNT1/$tdir/$tfile- 5

    $SETSTRIPE -o 0 $MOUNT2/f14b-3
    echo "data" > $MOUNT2/f14b-3
    createmany -o $MOUNT1/$tdir/$tfile-3- 5
    umount $MOUNT2

    fail $SINGLEMDS
    wait_recovery_complete $SINGLEMDS || error "MDS recovery not done"

    # first 25 files should have been replayed
    unlinkmany $MOUNT1/$tdir/$tfile- 5 || return 2
    unlinkmany $MOUNT1/$tdir/$tfile-3- 5 || return 3

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"

    wait_mds_ost_sync || return 4
    wait_delete_completed || return 5

    AFTERUSED=`df -P $DIR | tail -1 | awk '{ print $3 }'`
    log "before $BEFOREUSED, after $AFTERUSED"
    [ $AFTERUSED -ne $BEFOREUSED ] && \
        error "after $AFTERUSED > before $BEFOREUSED" && return 4
    return 0
}
run_test 14b "delete ost orphans if gap occured in objids due to VBR"

test_15a() { # was test_15
    replay_barrier $SINGLEMDS
    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1
    umount $MOUNT2

    fail $SINGLEMDS

    unlinkmany $MOUNT1/$tfile- 25 || return 2
    [ -e $MOUNT1/$tfile-2-0 ] && error "$tfile-2-0 exists"

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    return 0
}
run_test 15a "timeout waiting for lost client during replay, 1 client completes"

test_15c() {
    replay_barrier $SINGLEMDS
    for ((i = 0; i < 2000; i++)); do
        echo "data" > "$MOUNT2/${tfile}-$i" || error "create ${tfile}-$i failed"
    done
    umount $MOUNT2

    fail $SINGLEMDS

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    return 0
}
run_test 15c "remove multiple OST orphans"

test_16() {
    replay_barrier $SINGLEMDS
    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1
    umount $MOUNT2

    facet_failover $SINGLEMDS
    sleep $TIMEOUT
    fail $SINGLEMDS

    unlinkmany $MOUNT1/$tfile- 25 || return 2

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    return 0

}
run_test 16 "fail MDS during recovery (3571)"

test_17() {
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1

    # Make sure the disconnect is lost
    replay_barrier ost1
    umount $MOUNT2

    facet_failover ost1
    sleep $TIMEOUT
    fail ost1

    unlinkmany $MOUNT1/$tfile- 25 || return 2

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    return 0

}
run_test 17 "fail OST during recovery (3571)"

# cleanup with blocked enqueue fails until timer elapses (MDS busy), wait for it
export NOW=0

test_18() { # bug 3822 - evicting client with enqueued lock
    #set -vx
    mkdir -p $MOUNT1/$tdir
    touch $MOUNT1/$tdir/f0
#define OBD_FAIL_LDLM_ENQUEUE_BLOCKED    0x30b
    statmany -s $MOUNT1/$tdir/f 1 500 &
    OPENPID=$!
    NOW=`date +%s`
    do_facet $SINGLEMDS lctl set_param fail_loc=0x8000030b  # hold enqueue
    sleep 1
#define OBD_FAIL_LDLM_BL_CALLBACK        0x305
    do_facet client lctl set_param fail_loc=0x80000305  # drop cb, evict
    cancel_lru_locks mdc
    usleep 500 # wait to ensure first client is one that will be evicted
    openfile -f O_RDONLY $MOUNT2/$tdir/f0
    wait $OPENPID
    dmesg | grep "entering recovery in server" && \
        error "client not evicted" || true
    do_facet client "lctl set_param fail_loc=0"
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"
}
run_test 18 "ldlm_handle_enqueue succeeds on evicted export (3822)"

test_19() { # Bug 10991 - resend of open request does not fail assertion.
    replay_barrier $SINGLEMDS
    drop_ldlm_reply "createmany -o $DIR/$tfile 1" || return 1
    fail $SINGLEMDS
    checkstat $DIR2/${tfile}0 || return 2
    rm $DIR/${tfile}0 || return 3

    return 0
}
run_test 19 "resend of open request"

test_20() { #16389
    BEFORE=`date +%s`
    replay_barrier $SINGLEMDS
    touch $MOUNT1/a
    touch $MOUNT2/b
    umount $MOUNT2
    fail $SINGLEMDS
    rm $MOUNT1/a
    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    TIER1=$((`date +%s` - BEFORE))
    BEFORE=`date +%s`
    replay_barrier $SINGLEMDS
    touch $MOUNT1/a
    touch $MOUNT2/b
    umount $MOUNT2
    fail $SINGLEMDS
    rm $MOUNT1/a
    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    TIER2=$((`date +%s` - BEFORE))
    [ $TIER2 -ge $((TIER1 * 2)) ] && \
        error "recovery time is growing $TIER2 > $TIER1"
    return 0
}
run_test 20 "recovery time is not increasing"

# commit on sharing tests
test_21a() {
    local param_file=$TMP/$tfile-params

    save_lustre_params $(facet_active_host $SINGLEMDS) "mdt.*.commit_on_sharing" > $param_file
    do_facet $SINGLEMDS lctl set_param mdt.*.commit_on_sharing=1
    touch  $MOUNT1/$tfile-1
    mv  $MOUNT2/$tfile-1 $MOUNT2/$tfile-2
    mv  $MOUNT1/$tfile-2 $MOUNT1/$tfile-3
    replay_barrier_nosync $SINGLEMDS
    umount $MOUNT2

    facet_failover $SINGLEMDS

    # all renames are replayed
    unlink  $MOUNT1/$tfile-3 || return 2

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"

    do_facet $SINGLEMDS lctl set_param mdt.*.commit_on_sharing=0
    rm -rf $MOUNT1/$tfile-*
    restore_lustre_params < $param_file
    rm -f $param_file
    return 0
}
run_test 21a "commit on sharing"

test_21b_sub () {
    local mds=$1 
    do_node $CLIENT1 rm -f $MOUNT1/$tfile-*

    do_facet $mds sync
    do_node $CLIENT1 touch  $MOUNT1/$tfile-1
    do_node $CLIENT2 mv  $MOUNT1/$tfile-1 $MOUNT1/$tfile-2
    do_node $CLIENT1 mv  $MOUNT1/$tfile-2 $MOUNT1/$tfile-3

    replay_barrier_nosync $mds
    shutdown_client $CLIENT2 $MOUNT1

    facet_failover $mds

    # were renames replayed?
    local rc=0
    echo UNLINK $MOUNT1/$tfile-3 
    do_node $CLIENT1 unlink  $MOUNT1/$tfile-3 || \
        { echo "unlink $tfile-3 fail!" && rc=1; }

    boot_node $CLIENT2
    zconf_mount_clients $CLIENT2 $MOUNT1 || error "mount $CLIENT2 $MOUNT1 fail" 

    return $rc
}

test_21b() {
    [ -z "$CLIENTS" ] && skip "Need two or more clients." && return
    [ $CLIENTCOUNT -lt 2 ] && \
        { skip "Need two or more clients, have $CLIENTCOUNT" && return; }

    if [ "$FAILURE_MODE" = "HARD" ] &&  mixed_mdt_devs; then
        skip "Several mdt services on one mds node are used with FAILURE_MODE=$FAILURE_MODE. "
        return 0
    fi


    zconf_umount_clients $CLIENTS $MOUNT2
    zconf_mount_clients $CLIENTS $MOUNT1

    local param_file=$TMP/$tfile-params

    local num=$(get_mds_dir $MOUNT1)

    save_lustre_params $(facet_active_host mds$num) "mdt.*.commit_on_sharing" > $param_file

    # COS enabled
    local COS=1
    do_facet mds$num lctl set_param mdt.*.commit_on_sharing=$COS

    test_21b_sub mds$num || error "Not all renames are replayed. COS=$COS"

    # COS disabled (should fail)
    COS=0
    do_facet mds$num lctl set_param mdt.*.commit_on_sharing=$COS

    # there is still a window when transactions may be written to disk before
    # the mds device is set R/O. To avoid such a rare test failure, the check
    # is repeated several times.
    local n_attempts=1
    while true; do
    test_21b_sub mds$num || break;
    let n_attempts=n_attempts+1
    [ $n_attempts -gt 3 ] &&
        error "The test cannot check whether COS works or not: all renames are replied w/o COS"
    done
    restore_lustre_params < $param_file
    rm -f $param_file
    return 0
}
run_test 21b "commit on sharing, two clients"

# end commit on sharing tests 

complete $(basename $0) $SECONDS
SLEEP=$((`date +%s` - $NOW))
[ $SLEEP -lt $TIMEOUT ] && sleep $SLEEP
[ "$MOUNTED2" = yes ] && zconf_umount $HOSTNAME $MOUNT2 || true
check_and_cleanup_lustre
exit_status
