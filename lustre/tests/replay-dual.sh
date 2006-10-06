#!/bin/sh

set -e

# bug number:  6088 10124 10800
ALWAYS_EXCEPT="8    15c   17    $REPLAY_DUAL_EXCEPT"

PTLDEBUG=${PTLDEBUG:--1}
LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/lmv.sh}

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

build_test_filter

cleanup() {
    stopall
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w lnet.debug=0
    cleanup
    exit
fi

setup() {
    cleanup
    formatall
    setupall
    mount_client $MOUNT2
}

$SETUP
[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE

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
    multiop $MOUNT2/a o_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $MOUNT2/a o_c &
    pid1=$!
    multiop $MOUNT1/a o_c &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
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
    sysctl -w lustre.fail_loc=0x80000119
    fail $SINGLEMDS
    sysctl -w lustre.fail_loc=0

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
    sysctl -w lustre.fail_loc=0x80000119
    fail $SINGLEMDS
    sysctl -w lustre.fail_loc=0

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
    sysctl -w lustre.fail_loc=0x0119
    facet_failover $SINGLEMDS
    #sleep for while, let both clients reconnect and timeout
    sleep $((TIMEOUT * 2))
    sysctl -w lustre.fail_loc=0

    rm $MOUNT1/$tfile-[1-5] || return 1

    return 0
}
run_test 11 "both clients timeout during replay"

test_12() {
    replay_barrier $SINGLEMDS

    multiop $DIR/$tfile mo_c &
    MULTIPID=$!
    sleep 5

#define OBD_FAIL_LDLM_ENQUEUE            0x302
    sysctl -w lustre.fail_loc=0x80000302
    facet_failover $SINGLEMDS
    df $MOUNT || return 1
    sysctl -w lustre.fail_loc=0

    ls $DIR/$tfile
    kill -USR1 $MULTIPID || return 3
    wait $MULTIPID || return 4
    $CHECKSTAT -t file $DIR/$tfile || return 2
    rm $DIR/$tfile

    return 0
}
run_test 12 "open resend timeout"

test_13() {
    multiop $DIR/$tfile mo_c &
    MULTIPID=$!
    sleep 5

    replay_barrier $SINGLEMDS

    kill -USR1 $MULTIPID || return 3
    wait $MULTIPID || return 4

    # drop close 
    sysctl -w lustre.fail_loc=0x80000115
    facet_failover $SINGLEMDS
    df $MOUNT || return 1
    sysctl -w lustre.fail_loc=0

    ls $DIR/$tfile
    $CHECKSTAT -t file $DIR/$tfile || return 2
    rm $DIR/$tfile

    return 0
}
run_test 13 "close resend timeout"

test_14() {
    replay_barrier $SINGLEMDS
    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1
    createmany -o $MOUNT1/$tfile-3- 25
    umount $MOUNT2

    facet_failover $SINGLEMDS
    # expect failover to fail
    df $MOUNT && return 1
    sleep 1

    # first 25 files should have been replayed 
    unlinkmany $MOUNT1/$tfile- 25 || return 2

    zconf_mount `hostname` $MOUNT2
    return 0
}
run_test 14 "timeouts waiting for lost client during replay"

test_15() {
    replay_barrier $SINGLEMDS
    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1
    umount $MOUNT2

    facet_failover $SINGLEMDS
    df $MOUNT || return 1

    unlinkmany $MOUNT1/$tfile- 25 || return 2
    [ -e $MOUNT1/$tfile-2-0 ] && error "$tfile-2-0 exists"

    zconf_mount `hostname` $MOUNT2
    return 0
}
run_test 15 "timeout waiting for lost client during replay, 1 client completes"

test_15a() {
    local ost_last_id=""
    local osc_last_id=""
    
    replay_barrier $SINGLEMDS
    echo "data" > "$MOUNT2/${tfile}-m2"

    umount $MOUNT2
    facet_failover $SINGLEMDS
    df $MOUNT || return 1
    
    ost_last_id=`cat /proc/fs/lustre/obdfilter/*/last_id`
    mds_last_id=`cat /proc/fs/lustre/osc/*mds*/last_id`
    
    echo "Ids after MDS<->OST synchonizing"
    echo "--------------------------------"
    echo "MDS last_id:"
    echo $mds_last_id
    echo "OST last_id:"
    echo $ost_last_id

    local i=0
    echo $ost_last_id | while read id; do
	ost_ids[$i]=$id
	((i++))
    done
    
    i=0
    echo $mds_last_id | while read id; do
	mds_ids[$i]=$id
	((i++))
    done
    
    local arr_len=${#mds_ids[*]}
    for ((i=0;i<$arr_len;i++)); do
	    mds_id=${mds_ids[i]}
	    ost_id=${ost_ids[i]}
	    
	    test $mds_id -ge $ost_id || {
		echo "MDS last id ($mds_id) is smaller than OST one ($ost_id)"
		return 2
	    }
    done

    zconf_mount `hostname` $MOUNT2
    return 0
}
#CROW run_test 15a "OST clear orphans - synchronize ids on MDS and OST"

test_15b() {
    replay_barrier $SINGLEMDS
    echo "data" > "$MOUNT2/${tfile}-m2"
    umount $MOUNT2

    do_facet ost1 "sysctl -w lustre.fail_loc=0x80000802"
    facet_failover $SINGLEMDS

    df $MOUNT || return 1
    do_facet ost1 "sysctl -w lustre.fail_loc=0"
    
    zconf_mount `hostname` $MOUNT2
    return 0
}
#CROW run_test 15b "multiple delayed OST clear orphans"

test_15c() {
    replay_barrier $SINGLEMDS
    for ((i = 0; i < 2000; i++)); do
	echo "data" > "$MOUNT2/${tfile}-$i" || error "create ${tfile}-$i failed"
    done
    
    umount $MOUNT2
    facet_failover $SINGLEMDS

    df $MOUNT || return 1
    
    zconf_mount `hostname` $MOUNT2
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
    facet_failover $SINGLEMDS
    df $MOUNT || return 1

    unlinkmany $MOUNT1/$tfile- 25 || return 2

    zconf_mount `hostname` $MOUNT2
    return 0

}
run_test 16 "fail MDS during recovery (3571)"

test_17() {
    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1

    # Make sure the disconnect is lost
    replay_barrier ost1
    umount $MOUNT2

    facet_failover ost1
    sleep $TIMEOUT
    facet_failover ost1
    df $MOUNT || return 1

    unlinkmany $MOUNT1/$tfile- 25 || return 2

    zconf_mount `hostname` $MOUNT2
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
   do_facet $SINGLEMDS sysctl -w lustre.fail_loc=0x8000030b  # hold enqueue
   sleep 1
#define OBD_FAIL_LDLM_BL_CALLBACK        0x305
   do_facet client sysctl -w lustre.fail_loc=0x80000305  # drop cb, evict
   cancel_lru_locks mdc
   usleep 500 # wait to ensure first client is one that will be evicted
   openfile -f O_RDONLY $MOUNT2/$tdir/f0
   wait $OPENPID
   dmesg | grep "entering recovery in server" && \
      error "client not evicted" || true
}
run_test 18 "ldlm_handle_enqueue succeeds on evicted export (3822)"

if [ "$ONLY" != "setup" ]; then
   equals_msg test complete, cleaning up
   SLEEP=$((`date +%s` - $NOW))
   [ $SLEEP -lt $TIMEOUT ] && sleep $SLEEP
   $CLEANUP
fi
