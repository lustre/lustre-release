#!/bin/bash

set -e

PTLDEBUG=${PTLDEBUG:--1}
LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

# While we do not use OSTCOUNT=1 setup anymore,
# ost1failover_HOST is used
#ostfailover_HOST=${ostfailover_HOST:-$ost_HOST}
#failover= must be defined in OST_MKFS_OPTIONS if ostfailover_HOST != ost_HOST

remote_ost_nodsh && skip "remote OST with nodsh" && exit 0

if [ "$FAILURE_MODE" = "HARD" ] && mixed_ost_devs; then
    skip "$0: Several ost services on one ost node are used with FAILURE_MODE=$FAILURE_MODE. "
    exit 0
fi

# Tests that fail on uml
CPU=`awk '/model/ {print $4}' /proc/cpuinfo`
[ "$CPU" = "UML" ] && EXCEPT="$EXCEPT 6"

# Skip these tests
# BUG NUMBER: 
ALWAYS_EXCEPT="$REPLAY_OST_SINGLE_EXCEPT"

#					
[ "$SLOW" = "no" ] && EXCEPT_SLOW="5"

build_test_filter

check_and_setup_lustre
assert_DIR
rm -rf $DIR/[df][0-9]*

TDIR=$DIR/d0.${TESTSUITE}
mkdir -p $TDIR 
$LFS setstripe $TDIR -i 0 -c 1
$LFS getstripe $TDIR

test_0a() {
    zconf_umount `hostname` $MOUNT -f
    # needs to run during initial client->OST connection
    #define OBD_FAIL_OST_ALL_REPLY_NET       0x211
    do_facet ost1 "lctl set_param fail_loc=0x80000211"
    zconf_mount `hostname` $MOUNT && df $MOUNT || error "0a mount fail"
}
run_test 0a "target handle mismatch (bug 5317) `date +%H:%M:%S`"

test_0b() {
    fail ost1
    cp /etc/profile  $TDIR/$tfile
    sync
    diff /etc/profile $TDIR/$tfile
    rm -f $TDIR/$tfile
}
run_test 0b "empty replay"

test_1() {
    date > $TDIR/$tfile
    fail ost1
    $CHECKSTAT -t file $TDIR/$tfile || return 1
    rm -f $TDIR/$tfile
}
run_test 1 "touch"

test_2() {
    for i in `seq 10`; do
        echo "tag-$i" > $TDIR/$tfile-$i
    done 
    fail ost1
    for i in `seq 10`; do
      grep -q "tag-$i" $TDIR/$tfile-$i || error "f2-$i"
    done 
    rm -f $TDIR/$tfile-*
}
run_test 2 "|x| 10 open(O_CREAT)s"

test_3() {
    verify=$ROOT/tmp/verify-$$
    dd if=/dev/urandom bs=4096 count=1280 | tee $verify > $TDIR/$tfile &
    ddpid=$!
    sync &
    fail ost1
    wait $ddpid || return 1
    cmp $verify $TDIR/$tfile || return 2
    rm -f $verify $TDIR/$tfile
}
run_test 3 "Fail OST during write, with verification"

test_4() {
    verify=$ROOT/tmp/verify-$$
    dd if=/dev/urandom bs=4096 count=1280 | tee $verify > $TDIR/$tfile
    # invalidate cache, so that we're reading over the wire
    cancel_lru_locks osc
    cmp $verify $TDIR/$tfile &
    cmppid=$!
    fail ost1
    wait $cmppid || return 1
    rm -f $verify $TDIR/$tfile
}
run_test 4 "Fail OST during read, with verification"

test_5() {
    [ -z "`which iozone 2> /dev/null`" ] && skip "iozone missing" && return 0
    FREE=`df -P $TDIR | tail -n 1 | awk '{ print $4/2 }'`
    GB=1048576  # 1048576KB == 1GB
    if (( FREE > GB )); then
        FREE=$GB
    fi
    IOZONE_OPTS="-i 0 -i 1 -i 2 -+d -r 4 -s $FREE"
    iozone $IOZONE_OPTS -f $TDIR/$tfile &
    PID=$!
    
    sleep 8
    fail ost1
    wait $PID
    RC=$?
    log "iozone rc=$RC"
    rm -f $TDIR/$tfile
    [ $RC -ne 0 ] && return $RC || true
}
run_test 5 "Fail OST during iozone"

kbytesfree() {
   calc_osc_kbytes kbytesfree
}

test_6() {
    remote_mds_nodsh && skip "remote MDS with nodsh" && return 0

    f=$TDIR/$tfile
    rm -f $f
    sync && sleep 2 && sync	# wait for delete thread
    before=`kbytesfree`
    dd if=/dev/urandom bs=4096 count=1280 of=$f || return 28
    lfs getstripe $f
    get_stripe_info client $f

    sync
    sleep 2					# ensure we have a fresh statfs
    sync
#define OBD_FAIL_MDS_REINT_NET_REP       0x119
    do_facet mds "lctl set_param fail_loc=0x80000119"
    after_dd=`kbytesfree`
    log "before: $before after_dd: $after_dd"
    (( $before > $after_dd )) || return 1
    rm -f $f
    fail ost$((stripe_index + 1))
    $CHECKSTAT -t file $f && return 2 || true
    sync
    # let the delete happen
    sleep 5
    after=`kbytesfree`
    log "before: $before after: $after"
    (( $before <= $after + 40 )) || return 3	# take OST logs into account
}
run_test 6 "Fail OST before obd_destroy"

test_7() {
    f=$TDIR/$tfile
    rm -f $f
    sync && sleep 2 && sync	# wait for delete thread
    before=`kbytesfree`
    dd if=/dev/urandom bs=4096 count=1280 of=$f || return 4
    sync
    sleep 2					# ensure we have a fresh statfs
    sync
    after_dd=`kbytesfree`
    log "before: $before after_dd: $after_dd"
    (( $before > $after_dd )) || return 1
    replay_barrier ost1
    rm -f $f
    fail ost1
    $CHECKSTAT -t file $f && return 2 || true
    sync
    # let the delete happen
    sleep 2
    after=`kbytesfree`
    log "before: $before after: $after"
    (( $before <= $after + 40 )) || return 3	# take OST logs into account
}
run_test 7 "Fail OST before obd_destroy"

equals_msg `basename $0`: test complete, cleaning up
check_and_cleanup_lustre
[ -f "$TESTSUITELOG" ] && cat $TESTSUITELOG && grep -q FAIL $TESTSUITELOG && exit 1 || true
