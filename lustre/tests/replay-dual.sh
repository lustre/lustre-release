#!/bin/sh

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/lmv.sh}

gen_config() {
    rm -f $XMLCONFIG
    if [ "$MDSCOUNT" -gt 1 ]; then
        add_lmv lmv1
        for mds in `mds_list`; do
            MDSDEV=$TMP/${mds}-`hostname`
            add_mds $mds --dev $MDSDEV --size $MDSSIZE  --lmv lmv1
        done
        add_lov_to_lmv lov1 lmv1 --stripe_sz $STRIPE_BYTES \
	    --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
	MDS=lmv1
    else
        add_mds mds1 --dev $MDSDEV --size $MDSSIZE
        add_lov lov1 mds1 --stripe_sz $STRIPE_BYTES \
	    --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
	MDS=mds1_svc

    fi

    add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE
    add_ost ost2 --lov lov1 --dev ${OSTDEV}-2 --size $OSTSIZE
    add_client client --mds ${MDS} --lov lov1 --path $MOUNT
}



build_test_filter

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

cleanup() {
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activemds=`facet_active mds1`
    if [ $activemds != "mds1" ]; then
        fail mds1
    fi

    umount $MOUNT2 || true
    umount $MOUNT || true
    rmmod llite
    for mds in `mds_list`; do
	stop $mds ${FORCE} $MDSLCONFARGS
    done
    stop ost2 ${FORCE}
    stop ost ${FORCE}  --dump cleanup-dual.log
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0
    cleanup
    exit
fi

setup() {
    gen_config
    start ost --reformat $OSTLCONFARGS 
    PINGER=`cat /proc/fs/lustre/pinger`

    if [ "$PINGER" != "on" ]; then
	echo "ERROR: Lustre must be built with --enable-pinger for replay-dual"
	stop ost
	exit 1
    fi

    start ost2 --reformat $OSTLCONFARGS 
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    for mds in `mds_list`; do
	start $mds --reformat $MDSLCONFARGS
    done
    grep " $MOUNT " /proc/mounts || zconf_mount `hostname` $MOUNT
    grep " $MOUNT2 " /proc/mounts || zconf_mount `hostname` $MOUNT2

    echo $TIMEOUT > /proc/sys/lustre/timeout
    echo $UPCALL > /proc/sys/lustre/upcall
}

$SETUP
[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE


test_1() {
    touch $MOUNT1/a
    replay_barrier mds1
    touch $MOUNT2/b

    fail mds1
    checkstat $MOUNT2/a || return 1
    checkstat $MOUNT1/b || return 2
    rm $MOUNT2/a $MOUNT1/b
    checkstat $MOUNT1/a && return 3
    checkstat $MOUNT2/b && return 4
    return 0
}

run_test 1 "|X| simple create"


test_2() {
    replay_barrier mds1
    mkdir $MOUNT1/adir

    fail mds1
    checkstat $MOUNT2/adir || return 1
    rmdir $MOUNT2/adir
    checkstat $MOUNT2/adir && return 2
    return 0
}

run_test 2 "|X| mkdir adir"

test_3() {
    replay_barrier mds1
    mkdir $MOUNT1/adir
    mkdir $MOUNT2/adir/bdir

    fail mds1
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
    replay_barrier mds1
    mkdir $MOUNT1/adir  && return 1
    mkdir $MOUNT2/adir/bdir

    fail mds1
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
    replay_barrier mds1
    kill -USR1 $pid
    wait $pid || return 1

    fail mds1
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
    replay_barrier mds1
    kill -USR1 $pid1
    wait $pid1 || return 1

    fail mds1
    kill -USR1 $pid2
    wait $pid2 || return 1
    [ -e $MOUNT2/a ] && return 2
    return 0
}
run_test 6 "open1, open2, unlink |X| close1 [fail mds] close2"

test_6b() {
    mcreate $MOUNT1/a
    multiop $MOUNT2/a o_c &
    pid1=$!
    multiop $MOUNT1/a o_c &
    pid2=$!
    # give multiop a chance to open
    sleep 1
    rm -f $MOUNT1/a
    replay_barrier mds1
    kill -USR1 $pid2
    wait $pid2 || return 1

    fail mds1
    kill -USR1 $pid1
    wait $pid1 || return 1
    [ -e $MOUNT2/a ] && return 2
    return 0
}
run_test 6b "open1, open2, unlink |X| close2 [fail mds] close1"

test_7() {
    replay_barrier mds1
    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1
    createmany -o $MOUNT1/$tfile-3- 25
    umount $MOUNT2

    facet_failover mds1
    # expect failover to fail
    df $MOUNT && return 1

#   3313 - current fix for 3313 prevents any reply here
#    unlinkmany $MOUNT1/$tfile- 25 || return 2

    zconf_mount `hostname` $MOUNT2
    return 0
}
run_test 7 "timeouts waiting for lost client during replay"


test_8() {
    replay_barrier mds1
    drop_reint_reply "mcreate $MOUNT1/$tfile"    || return 1
    fail mds1
    checkstat $MOUNT2/$tfile || return 2
    rm $MOUNT1/$tfile || return 3

    return 0
}
run_test 8 "replay of resent request"

test_9() {
    replay_barrier mds1
    mcreate $MOUNT1/$tfile-1
    mcreate $MOUNT2/$tfile-2
    # drop first reint reply
    sysctl -w lustre.fail_loc=0x80000119
    fail mds1
    sysctl -w lustre.fail_loc=0

    rm $MOUNT1/$tfile-[1,2] || return 1

    return 0
}
run_test 9 "resending a replayed create"

test_10() {
    mcreate $MOUNT1/$tfile-1
    replay_barrier mds1
    munlink $MOUNT1/$tfile-1
    mcreate $MOUNT2/$tfile-2
    # drop first reint reply
    sysctl -w lustre.fail_loc=0x80000119
    fail mds1
    sysctl -w lustre.fail_loc=0

    checkstat $MOUNT1/$tfile-1 && return 1
    checkstat $MOUNT1/$tfile-2 || return 2
    rm $MOUNT1/$tfile-2

    return 0
}
run_test 10 "resending a replayed unlink"

test_11() {
    replay_barrier mds1
    mcreate $MOUNT1/$tfile-1
    mcreate $MOUNT2/$tfile-2
    mcreate $MOUNT1/$tfile-3
    mcreate $MOUNT2/$tfile-4
    mcreate $MOUNT1/$tfile-5
    # drop all reint replies for a while
    sysctl -w lustre.fail_loc=0x0119
    facet_failover mds1
    #sleep for while, let both clients reconnect and timeout
    sleep $((TIMEOUT * 2))
    sysctl -w lustre.fail_loc=0

    rm $MOUNT1/$tfile-[1-5] || return 1

    return 0
}
run_test 11 "both clients timeout during replay"

test_12() {
    replay_barrier mds1

    multiop $DIR/$tfile mo_c &
    MULTIPID=$!
    sleep 5

    # drop first enqueue
    sysctl -w lustre.fail_loc=0x80000302
    facet_failover mds1
    df $MOUNT || return 1
    sysctl -w lustre.fail_loc=0

    ls $DIR/$tfile
    $CHECKSTAT -t file $DIR/$tfile || return 2
    kill -USR1 $MULTIPID || return 3
    wait $MULTIPID || return 4
    rm $DIR/$tfile

    return 0
}
run_test 12 "open resend timeout"

test_13() {
    multiop $DIR/$tfile mo_c &
    MULTIPID=$!
    sleep 5

    replay_barrier mds1

    kill -USR1 $MULTIPID || return 3
    wait $MULTIPID || return 4

    # drop close 
    sysctl -w lustre.fail_loc=0x80000115
    facet_failover mds1
    df $MOUNT || return 1
    sysctl -w lustre.fail_loc=0

    ls $DIR/$tfile
    $CHECKSTAT -t file $DIR/$tfile || return 2
    rm $DIR/$tfile

    return 0
}
run_test 13 "close resend timeout"

test_20 () {
    replay_barrier mds1
    multiop $MOUNT2/$tfile O_c &
    pid2=$!
    multiop $MOUNT1/$tfile O_c &
    pid1=$!
    # give multiop a chance to open
    sleep 1 
    kill -USR1 $pid2
    kill -USR1 $pid1
    sleep 1
    umount $MOUNT2
    facet_failover mds1
    df || df ||  return 1
    zconf_mount `hostname` $MOUNT2
}
run_test 20 "replay open, Abort recovery, don't assert (3892)"

if [ "$ONLY" != "setup" ]; then
	equals_msg test complete, cleaning up
	$CLEANUP
fi
