#!/bin/sh

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env

# XXX I wish all this stuff was in some default-config.sh somewhere
mds_HOST=${mds_HOST:-`hostname`}
mdsfailover_HOST=${mdsfailover_HOST}
ost_HOST=${ost_HOST:-`hostname`}
client_HOST=${client_HOST:-`hostname`}

NETTYPE=${NETTYPE:-tcp}

PDSH=${PDSH:-no_dsh}
MOUNT=${MOUNT:-/mnt/lustre}
MDSDEV=${MDSDEV:-/tmp/mds-`hostname`}
MDSSIZE=${MDSSIZE:-100000}
OSTDEV=${OSTDEV:-/tmp/ost-`hostname`}
OSTSIZE=${OSTSIZE:-100000}
MOUNT1=${MOUNT1:-${MOUNT}1}
MOUNT2=${MOUNT2:-${MOUNT}2}
UPCALL=${UPCALL:-$PWD/replay-single-upcall.sh}
FSTYPE=${FSTYPE:-ext3}
TIMEOUT=${TIMEOUT:-5}

STRIPE_BYTES=65536
STRIPES_PER_OBJ=1

gen_config() {
    rm -f replay-dual.xml
    add_facet mds
    add_facet ost
    add_facet client --lustre_upcall $UPCALL
    do_lmc --add mds --node mds_facet --mds mds1 --dev $MDSDEV --size $MDSSIZE
    do_lmc --add lov --mds mds1 --lov lov1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
    do_lmc --add ost --lov lov1 --node ost_facet --ost ost1 --dev $OSTDEV --size $OSTSIZE
    do_lmc --add ost --lov lov1 --node ost_facet --ost ost2 --dev ${OSTDEV}-2 --size $OSTSIZE
    do_lmc --add mtpt --node client_facet --path $MOUNT --mds mds1 --ost lov1
}


build_test_filter

cleanup() {
    [ "$DAEMONFILE" ] && lctl debug_daemon stop
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activemds=`facet_active mds`
    if [ $activemds != "mds" ]; then
        fail mds
    fi

    lconf  --cleanup --zeroconf --mds_uuid mds1_UUID --mds_nid $mds_HOST \
       --local_nid $client_HOST --profile client_facet --mount $MOUNT
    lconf  --cleanup --zeroconf --mds_uuid mds1_UUID --mds_nid $mds_HOST \
       --local_nid $client_HOST --profile client_facet --mount $MOUNT2
    stop mds ${FORCE} --dump cleanup-dual.log
    stop ost ${FORCE}
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0
    cleanup
    exit
fi

gen_config
start mds --write_conf --reformat
start ost --reformat
start mds
PINGER=`cat /proc/fs/lustre/pinger`

if [ "$PINGER" != "on" ]; then
    echo "ERROR: Lustre must be built with --enable-pinger for replay-dual"
    stop mds
    exit 1
fi

# 0-conf client
lconf --zeroconf --mds_uuid mds1_UUID --mds_nid `h2$NETTYPE $mds_HOST` \
    --local_nid `h2$NETTYPE $client_HOST` --profile client_facet --mount $MOUNT
lconf --zeroconf --mds_uuid mds1_UUID --mds_nid `h2$NETTYPE $mds_HOST` \
    --local_nid `h2$NETTYPE $client_HOST` --profile client_facet --mount $MOUNT2

echo $TIMEOUT > /proc/sys/lustre/timeout
echo $UPCALL > /proc/sys/lustre/upcall

[ "$DAEMONFILE" ] && lctl debug_daemon start $DAEMONFILE $DAEMONSIZE

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


equals_msg test complete, cleaning up
