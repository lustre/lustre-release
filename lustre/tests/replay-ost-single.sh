#!/bin/sh

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

ostfailover_HOST=${ostfailover_HOST:-$ost_HOST}

# Skip these tests
ALWAYS_EXCEPT=""

gen_config() {
    rm -f $XMLCONFIG
    add_mds mds --dev $MDSDEV --size $MDSSIZE
    add_lov lov1 mds --stripe_sz $STRIPE_BYTES\
	--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
    add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE --failover
    if [ ! -z "$ostfailover_HOST" ]; then
	 add_ostfailover ost --dev $OSTDEV --size $OSTSIZE
    fi
    add_client client mds --lov lov1 --path $MOUNT
}

cleanup() {
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activeost=`facet_active ost`
    if [ $activeost != "ost" ]; then
        fail ost
    fi
    zconf_umount $MOUNT
    stop mds ${FORCE} $MDSLCONFARGS
    stop ost ${FORCE} --dump cleanup.log
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0
    cleanup
    exit
fi

build_test_filter

rm -f ostactive

gen_config

start ost --reformat $OSTLCONFARGS
PINGER=`cat /proc/fs/lustre/pinger`

if [ "$PINGER" != "on" ]; then
    echo "ERROR: Lustre must be built with --enable-pinger for this test."
    stop ost
    exit 1
fi
[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
start mds --reformat $MDSLCONFARGS
zconf_mount $MOUNT

mkdir -p $DIR

test_0() {
    replay_barrier ost
    fail ost
    cp /etc/profile  $DIR/$tfile
    sync
    diff /etc/profile $DIR/$tfile
}
run_test 0 "empty replay"

test_1() {
    replay_barrier ost
    date > $DIR/$tfile
    fail ost
    $CHECKSTAT -t file $DIR/$tfile || return 1
}
run_test 1 "touch"

test_2() {
    replay_barrier ost
    for i in `seq 10`; do
        echo "tag-$i" > $DIR/$tfile-$i
    done 
    fail ost
    for i in `seq 10`; do
      grep -q "tag-$i" $DIR/$tfile-$i || error "f1c-$i"
    done 
}
run_test 2 "|x| 10 open(O_CREAT)s"

test_3() {
    verify=$ROOT/tmp/verify-$$
    dd if=/dev/urandom bs=1024 count=5120 | tee $verify > $DIR/$tfile &
    ddpid=$!
    sync &
    fail ost
    wait $ddpid || return 1
    cmp $verify $DIR/$tfile || return 2
    rm $verify
}
run_test 3 "Fail OST during write, with verification"

equals_msg test complete, cleaning up
cleanup

