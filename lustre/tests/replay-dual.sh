#!/bin/sh

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

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

    umount $MOUNT2
    umount $MOUNT
    rmmod llite
    stop mds ${FORCE}
    stop ost2 ${FORCE}
    stop ost ${FORCE}  --dump cleanup-dual.log
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0
    cleanup
    exit
fi

gen_config
start ost --reformat $OSTLCONFARGS 
PINGER=`cat /proc/fs/lustre/pinger`

if [ "$PINGER" != "on" ]; then
    echo "ERROR: Lustre must be built with --enable-pinger for replay-dual"
    stop mds
    exit 1
fi

start ost2 --reformat $OSTLCONFARGS 
[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
start mds $MDSLCONFARGS --reformat
zconf_mount $MOUNT
zconf_mount $MOUNT2

echo $TIMEOUT > /proc/sys/lustre/timeout
echo $UPCALL > /proc/sys/lustre/upcall

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
    multiop $MOUNT2/a o_tSc &
    pid=$!
    # give multiop a chance to open
    sleep 1 
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
    multiop $MOUNT2/a o_c &
    pid1=$!
    multiop $MOUNT1/a o_c &
    pid2=$!
    # give multiop a chance to open
    sleep 1 
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


if [ "$ONLY" != "setup" ]; then
	equals_msg test complete, cleaning up
	cleanup
fi
