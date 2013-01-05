#!/bin/bash

set -e

# bug number:  10124 19884
ALWAYS_EXCEPT="15c 14b  $REPLAY_DUAL_EXCEPT"

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

require_dsh_mds || exit 0

[ "$SLOW" = "no" ] && EXCEPT_SLOW="1 2 3 4 5 14"

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
    multiop_bg_pause $MOUNT2/a o_tSc || return  1
    pid=$!
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
    multiop_bg_pause $MOUNT2/a o_c || return 1
    pid1=$!
    multiop_bg_pause $MOUNT1/a o_c || return 1
    pid2=$!
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

test_8() {
    replay_barrier mds
    drop_reint_reply "mcreate $MOUNT1/$tfile"    || return 1
    fail mds
    checkstat $MOUNT2/$tfile || return 2
    rm $MOUNT1/$tfile || return 3

    return 0
}
run_test 8 "replay of resent request"

test_9() {
    replay_barrier mds
    mcreate $MOUNT1/$tfile-1
    mcreate $MOUNT2/$tfile-2
    # drop first reint reply
    do_facet mds lctl set_param fail_loc=0x80000119
    fail mds
    do_facet mds lctl set_param fail_loc=0

    rm $MOUNT1/$tfile-[1,2] || return 1

    return 0
}
run_test 9 "resending a replayed create"

test_10() {
    mcreate $MOUNT1/$tfile-1
    replay_barrier mds
    munlink $MOUNT1/$tfile-1
    mcreate $MOUNT2/$tfile-2
    # drop first reint reply
    do_facet mds lctl set_param fail_loc=0x80000119
    fail mds
    do_facet mds lctl set_param fail_loc=0

    checkstat $MOUNT1/$tfile-1 && return 1
    checkstat $MOUNT1/$tfile-2 || return 2
    rm $MOUNT1/$tfile-2

    return 0
}
run_test 10 "resending a replayed unlink"

test_11() {
    replay_barrier mds
    mcreate $MOUNT1/$tfile-1
    mcreate $MOUNT2/$tfile-2
    mcreate $MOUNT1/$tfile-3
    mcreate $MOUNT2/$tfile-4
    mcreate $MOUNT1/$tfile-5
    # drop all reint replies for a while
    do_facet mds lctl set_param fail_loc=0x0119
    # note that with this fail_loc set, facet_failover df will fail
    facet_failover mds
    #sleep for while, let both clients reconnect and timeout
    sleep $((TIMEOUT * 2))
    do_facet mds lctl set_param fail_loc=0
    clients_up
    while [ -z "$(ls $MOUNT1/$tfile-[1-5] 2>/dev/null)" ]; do
	sleep 5
	echo -n "."
    done
    ls $MOUNT1/$tfile-[1-5]
    rm $MOUNT1/$tfile-[1-5] || return 1

    return 0
}
run_test 11 "both clients timeout during replay"

test_12() {
    replay_barrier mds

    multiop_bg_pause $DIR/$tfile mo_c || return 1
    MULTIPID=$!

#define OBD_FAIL_LDLM_ENQUEUE            0x302
    do_facet mds lctl set_param fail_loc=0x80000302
    facet_failover mds
    do_facet mds lctl set_param fail_loc=0
    clients_up || { kill -USR1 $MULTIPID  && return 1; }

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

    replay_barrier mds

    kill -USR1 $MULTIPID || return 3
    wait $MULTIPID || return 4

    # drop close
    do_facet mds lctl set_param fail_loc=0x80000115
    facet_failover mds
    do_facet mds lctl set_param fail_loc=0
    clients_up || return 1

    ls $DIR/$tfile
    $CHECKSTAT -t file $DIR/$tfile || return 2
    rm $DIR/$tfile

    return 0
}
run_test 13 "close resend timeout"

test_14a() {
    # interop 18 <-> 20
    local lustre_version=$(get_lustre_version mds)
    if [[ $lustre_version != 1.8* ]]; then
        skip "mds is running $lustre_version, test is obsoleted"
        return 0
    fi
    replay_barrier mds
    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1
    createmany -o $MOUNT1/$tfile-3- 25
    umount $MOUNT2

    facet_failover mds
    # expect recovery to fail due to missing client 2
    client_evicted || return 1
    sleep 1

    # first 25 files should have been replayed
    unlinkmany $MOUNT1/$tfile- 25 || return 2

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    return 0
}
run_test 14a "timeouts waiting for lost client during replay"

test_14b() {
    wait_mds_ost_sync
    wait_delete_completed
    BEFOREUSED=`df -P $DIR | tail -1 | awk '{ print $3 }'`
    #lfs setstripe --index=0 --count=1 $MOUNT1
    mkdir -p $MOUNT1/$tdir
    #lfs setstripe --index=0 --count=1 $MOUNT1/$tdir
    replay_barrier mds
    createmany -o $MOUNT1/$tfile- 5
    echo "data" > $MOUNT2/$tdir/$tfile-2
    createmany -o $MOUNT1/$tfile-3- 5
    umount $MOUNT2

    fail mds
    wait_recovery_complete mds || error "MDS recovery isn't done"

    # first 25 files should have been replayed
    unlinkmany $MOUNT1/$tfile- 5 || return 2
    unlinkmany $MOUNT1/$tfile-3- 5 || return 3

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"

    wait_mds_ost_sync || return 5
    wait_delete_completed || return 6

    AFTERUSED=`df -P $DIR | tail -1 | awk '{ print $3 }'`
    log "before $BEFOREUSED, after $AFTERUSED"
    [ $AFTERUSED -ne $BEFOREUSED ] && \
        error "after $AFTERUSED > before $BEFOREUSED" && return 4
    return 0
}
run_test 14b "delete ost orphans if gap occured in objids due to VBR"

test_15a() { # was test_15
    replay_barrier mds
    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1
    umount $MOUNT2

    fail mds

    unlinkmany $MOUNT1/$tfile- 25 || return 2
    [ -e $MOUNT1/$tfile-2-0 ] && error "$tfile-2-0 exists"

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    return 0
}
run_test 15a "timeout waiting for lost client during replay, 1 client completes"

test_15c() {
    replay_barrier mds
    for ((i = 0; i < 2000; i++)); do
        echo "data" > "$MOUNT2/${tfile}-$i" || error "create ${tfile}-$i failed"
    done

    umount $MOUNT2
    fail mds

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    return 0
}
run_test 15c "remove multiple OST orphans"

test_16() {
    replay_barrier mds
    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1
    umount $MOUNT2

    facet_failover mds
    sleep $TIMEOUT
    fail mds

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
    do_facet mds lctl set_param fail_loc=0x8000030b  # hold enqueue
    sleep 1
#define OBD_FAIL_LDLM_BL_CALLBACK        0x305
    do_facet client lctl set_param fail_loc=0x80000305  # drop cb, evict
    cancel_lru_locks mdc
    sleep 0.500s # wait to ensure first client is one that will be evicted
    openfile -f O_RDONLY $MOUNT2/$tdir/f0
    wait $OPENPID
    dmesg | grep "entering recovery in server" && \
        error "client not evicted" || true
}
run_test 18 "ldlm_handle_enqueue succeeds on evicted export (3822)"

test_19() { # Bug 10991 - resend of open request does not fail assertion.
    replay_barrier mds
    drop_ldlm_reply "createmany -o $DIR/$tfile 1" || return 1
    fail mds
    checkstat $DIR2/${tfile}0 || return 2
    rm $DIR/${tfile}0 || return 3

    return 0
}
run_test 19 "resend of open request"

test_20() { #16389
    BEFORE=`date +%s`
    replay_barrier mds
    touch $MOUNT1/a
    touch $MOUNT2/b
    umount $MOUNT2
    fail mds
    rm $MOUNT1/a
    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    TIER1=$((`date +%s` - BEFORE))
    BEFORE=`date +%s`
    replay_barrier mds
    touch $MOUNT1/a
    touch $MOUNT2/b
    umount $MOUNT2
    fail mds
    rm $MOUNT1/a
    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    TIER2=$((`date +%s` - BEFORE))
    [ $TIER2 -ge $((TIER1 * 2)) ] && \
        error "recovery time is growing $TIER2 > $TIER1"
    return 0
}
run_test 20 "recovery time is not increasing"

test_22() { #bug 18927
    multiop_bg_pause $MOUNT1/$tfile O_c || return 1
    pid1=$!
    multiop_bg_pause $MOUNT2/$tfile O_c || return 2
    pid2=$!
    rm -f $MOUNT1/$tfile
    replay_barrier mds
    fail mds
    kill -USR1 $pid1
    wait $pid1 || return 3
    kill -USR1 $pid2
    wait $pid2 || return 4
    [ -e $MOUNT1/$tfile ] && return 5
    return 0
}
run_test 22 "double open|creat in replay with open orphan from two mntp"

complete $(basename $0) $SECONDS
SLEEP=$((`date +%s` - $NOW))
[ $SLEEP -lt $TIMEOUT ] && sleep $SLEEP
[ "$MOUNTED2" = yes ] && zconf_umount $HOSTNAME $MOUNT2 || true
check_and_cleanup_lustre
exit_status
