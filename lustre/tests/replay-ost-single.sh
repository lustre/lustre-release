#!/bin/sh

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

ostfailover_HOST=${ostfailover_HOST:-$ost_HOST}

# Skip these tests
ALWAYS_EXCEPT="5"
# test 5 needs a larger fs than what local normally has

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
    zconf_umount `hostname` $MOUNT
    stop mds ${FORCE} $MDSLCONFARGS
    stop ost ${FORCE} --dump cleanup.log
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0
    cleanup
    exit
fi

build_test_filter

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

setup() {
    gen_config

    start ost --reformat $OSTLCONFARGS
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    start mds --reformat $MDSLCONFARGS
    zconf_mount `hostname` $MOUNT
}

mkdir -p $DIR

$SETUP

test_0() {
    fail ost
    cp /etc/profile  $DIR/$tfile
    sync
    diff /etc/profile $DIR/$tfile
    rm -f $DIR/$tfile
}
run_test 0 "empty replay"

test_1() {
    date > $DIR/$tfile
    fail ost
    $CHECKSTAT -t file $DIR/$tfile || return 1
    rm -f $DIR/$tfile
}
run_test 1 "touch"

test_2() {
    for i in `seq 10`; do
        echo "tag-$i" > $DIR/$tfile-$i
    done 
    fail ost
    for i in `seq 10`; do
      grep -q "tag-$i" $DIR/$tfile-$i || error "f2-$i"
    done 
    rm -f $DIR/$tfile-*
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
    rm -f $verify $DIR/$tfile
}
run_test 3 "Fail OST during write, with verification"

test_4() {
    verify=$ROOT/tmp/verify-$$
    dd if=/dev/urandom bs=1024 count=5120 | tee $verify > $DIR/$tfile
    # invalidate cache, so that we're reading over the wire
    for i in /proc/fs/lustre/ldlm/namespaces/OSC_*MNT*; do
        echo -n clear > $i/lru_size
    done
    cmp $verify $DIR/$tfile &
    cmppid=$!
    fail ost
    wait $cmppid || return 1
    rm -f $verify $DIR/$tfile
}
run_test 4 "Fail OST during read, with verification"

test_5() {
    IOZONE_OPTS="-i 0 -i 1 -i 2 -+d -r 64 -s 1g"
    iozone $IOZONE_OPTS -f $DIR/$tfile &
    PID=$!
    
    sleep 10
    fail ost
    wait $PID || return 1
    rm -f $DIR/$tfile
}
run_test 5 "Fail OST during iozone"

kbytesfree() {
   awk '{total+=$1} END {print total}' /proc/fs/lustre/osc/OSC_*MNT*/kbytesfree
}

test_6() {
    f=$DIR/$tfile
    rm -f $f
    sync && sleep 2 && sync	# wait for delete thread
    before=`kbytesfree`
    dd if=/dev/urandom bs=1024 count=5120 of=$f
#define OBD_FAIL_MDS_REINT_NET_REP       0x119
    do_facet mds "sysctl -w lustre.fail_loc=0x80000119"
    sync
    sleep 1					# ensure we have a fresh statfs
    after_dd=`kbytesfree`
    log "before: $before after_dd: $after_dd"
    (( $before > $after_dd )) || return 1
    rm -f $f
    fail ost
    $CHECKSTAT -t file $f && return 2 || true
    sync
    # let the delete happen
    sleep 2
    after=`kbytesfree`
    log "before: $before after: $after"
    (( $before <= $after + 40 )) || return 3	# take OST logs into account
}
run_test 6 "Fail OST before obd_destroy"

test_7() {
    f=$DIR/$tfile
    before=`kbytesfree`
    dd if=/dev/urandom bs=1024 count=5120 of=$f
    sync
    after_dd=`kbytesfree`
    echo "before: $before after_dd: $after_dd"
    (( before > after_dd )) || return 1
    replay_barrier ost
    rm -f $f
    fail ost
    $CHECKSTAT -t file $f && return 2 || true
    sync
    # let the delete happen
    sleep 2
    after=`kbytesfree`
    echo "before: $before after: $after"
    (( before == after )) || return 3
}
run_test 7 "Fail OST before obd_destroy"

equals_msg test complete, cleaning up
$CLEANUP
