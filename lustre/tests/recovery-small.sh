#!/bin/sh

set -e

#         bug 2732 2986
ALWAYS_EXCEPT="17   20b"


LUSTRE=${LUSTRE:-`dirname $0`/..}
UPCALL=${UPCALL:-$PWD/recovery-small-upcall.sh}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

build_test_filter


# Allow us to override the setup if we already have a mounted system by
# setting SETUP=" " and CLEANUP=" "
SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}


make_config() {
    rm -f $XMLCONFIG
    add_mds mds --dev $MDSDEV --size $MDSSIZE
    add_lov lov1 mds --stripe_sz $STRIPE_BYTES\
	--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
    add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE
    add_ost ost2 --lov lov1 --dev ${OSTDEV}-2 --size $OSTSIZE
    add_client client mds --lov lov1 --path $MOUNT
}

setup() {
    make_config
    start ost --reformat $OSTLCONFARGS 
    start ost2 --reformat $OSTLCONFARGS 
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    start mds $MDSLCONFARGS --reformat
    zconf_mount `hostname`  $MOUNT
}

cleanup() {
    zconf_umount `hostname` $MOUNT
    stop mds ${FORCE} $MDSLCONFARGS
    stop ost2 ${FORCE} --dump cleanup.log
    stop ost ${FORCE} --dump cleanup.log
}

replay() {
    do_mds "sync"
    do_mds 'echo -e "device \$mds1\\nprobe\\nnotransno\\nreadonly" | lctl'
    do_client "$1" &
    shutdown_mds -f
    start_mds
    wait
    do_client "df -h $MOUNT" # trigger failover, if we haven't already
}

if [ ! -z "$EVAL" ]; then
    eval "$EVAL"
    exit $?
fi

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0 || true
    cleanup
    exit
fi

REFORMAT=--reformat $SETUP
unset REFORMAT

test_1() {
    drop_request "mcreate $MOUNT/1"  || return 1
    drop_reply "mcreate $MOUNT/2"    || return 2
}
run_test 1 "mcreate: drop req, drop rep"

test_2() {
    drop_request "tchmod 111 $MOUNT/2"  || return 1
    drop_reply "tchmod 666 $MOUNT/2"    || return 2
}
run_test 2 "chmod: drop req, drop rep"

test_3() {
    drop_request "statone $MOUNT/2" || return 1
    drop_reply "statone $MOUNT/2"   || return 2
}
run_test 3 "stat: drop req, drop rep"

test_4() {
    do_facet client "cp /etc/resolv.conf $MOUNT/resolv.conf" || return 1
    drop_request "cat $MOUNT/resolv.conf > /dev/null"   || return 2
    drop_reply "cat $MOUNT/resolv.conf > /dev/null"     || return 3
}
run_test 4 "open: drop req, drop rep"

test_5() {
    drop_request "mv $MOUNT/resolv.conf $MOUNT/renamed" || return 1
    drop_reply "mv $MOUNT/renamed $MOUNT/renamed-again" || return 2
    do_facet client "checkstat -v $MOUNT/renamed-again"  || return 3
}
run_test 5 "rename: drop req, drop rep"

test_6() {
    drop_request "mlink $MOUNT/renamed-again $MOUNT/link1" || return 1
    drop_reply "mlink $MOUNT/renamed-again $MOUNT/link2"   || return 2
}
run_test 6 "link: drop req, drop rep"

test_7() {
    drop_request "munlink $MOUNT/link1"   || return 1
    drop_reply "munlink $MOUNT/link2"     || return 2
}
run_test 7 "unlink: drop req, drop rep"

#bug 1423
test_8() {
    drop_reply "touch $MOUNT/renamed"    || return 1
}
run_test 8 "touch: drop rep (bug 1423)"

#bug 1420
test_9() {
    pause_bulk "cp /etc/profile $MOUNT"       || return 1
    do_facet client "cp /etc/termcap $MOUNT"  || return 2
    do_facet client "sync"
    do_facet client "rm $MOUNT/termcap $MOUNT/profile" || return 3
}
run_test 9 "pause bulk on OST (bug 1420)"

#bug 1521
test_10() {
    do_facet client mcreate $MOUNT/f10        || return 1
    drop_bl_callback "chmod 0777 $MOUNT/f10"  || return 2
    # wait for the mds to evict the client
    #echo "sleep $(($TIMEOUT*2))"
    #sleep $(($TIMEOUT*2))
    do_facet client touch  $MOUNT/f10 || echo "touch failed, evicted"
    do_facet client checkstat -v -p 0777 $MOUNT/f10  || return 3
    do_facet client "munlink $MOUNT/f10"
}
run_test 10 "finish request on server after client eviction (bug 1521)"

#bug 2460
# wake up a thead waiting for completion after eviction
test_11(){
    do_facet client multiop $MOUNT/$tfile Ow  || return 1
    do_facet client multiop $MOUNT/$tfile or  || return 2

    cancel_lru_locks OSC

    do_facet client multiop $MOUNT/$tfile or  || return 3
    drop_bl_callback multiop $MOUNT/$tfile Ow  || 
        echo "client evicted, as expected"

    do_facet client munlink $MOUNT/$tfile  || return 4
}
run_test 11 "wake up a thead waiting for completion after eviction (b=2460)"

#b=2494
test_12(){
    $LCTL mark multiop $MOUNT/$tfile OS_c 
    do_facet mds "sysctl -w lustre.fail_loc=0x115"
    clear_failloc mds $((TIMEOUT * 2)) &
    multiop $MOUNT/$tfile OS_c  &
    PID=$!
#define OBD_FAIL_MDS_CLOSE_NET           0x115
    sleep 2
    kill -USR1 $PID
    echo "waiting for multiop $PID"
    wait $PID || return 2
    do_facet client munlink $MOUNT/$tfile  || return 3
}
run_test 12 "recover from timed out resend in ptlrpcd (b=2494)"

# Bug 113, check that readdir lost recv timeout works.
test_13() {
    mkdir /mnt/lustre/readdir
    touch /mnt/lustre/readdir/newentry
# OBD_FAIL_MDS_READPAGE_NET|OBD_FAIL_ONCE
    do_facet mds "sysctl -w lustre.fail_loc=0x80000104"
    ls /mnt/lustre/readdir || return 1
    do_facet mds "sysctl -w lustre.fail_loc=0"
    rm -rf /mnt/lustre/readdir
}
run_test 13 "mdc_readpage restart test (bug 1138)"

# Bug 113, check that readdir lost send timeout works.
test_14() {
    mkdir /mnt/lustre/readdir
    touch /mnt/lustre/readdir/newentry
# OBD_FAIL_MDS_SENDPAGE|OBD_FAIL_ONCE
    do_facet mds "sysctl -w lustre.fail_loc=0x80000106"
    ls /mnt/lustre/readdir || return 1
    do_facet mds "sysctl -w lustre.fail_loc=0"
}
run_test 14 "mdc_readpage resend test (bug 1138)"

test_15() {
    do_facet mds "sysctl -w lustre.fail_loc=0x80000128"
    touch $DIR/$tfile && return 1
    return 0
}
run_test 15 "failed open (-ENOMEM)"

test_16() {
    do_facet client cp /etc/termcap $MOUNT
    sync

#define OBD_FAIL_PTLRPC_BULK_PUT_NET 0x504 | OBD_FAIL_ONCE
    sysctl -w lustre.fail_loc=0x80000504
    cancel_lru_locks OSC
    # will get evicted here
    do_facet client "cmp /etc/termcap $MOUNT/termcap"  && return 1
    sysctl -w lustre.fail_loc=0
    do_facet client "cmp /etc/termcap $MOUNT/termcap"  || return 2
}
run_test 16 "timeout bulk put, evict client (2732)"

test_17() {
#define OBD_FAIL_PTLRPC_BULK_GET_NET 0x0503 | OBD_FAIL_ONCE
    # will get evicted here
    sysctl -w lustre.fail_loc=0x80000503
    do_facet client cp /etc/termcap $MOUNT && return 1

    do_facet client "cmp /etc/termcap $MOUNT/termcap"  && return 1
    sysctl -w lustre.fail_loc=0
    do_facet client "cmp /etc/termcap $MOUNT/termcap"  || return 2
}
run_test 17 "timeout bulk get, evict client (2732)"

test_18a() {
    do_facet client mkdir -p $MOUNT/$tdir
    f=$MOUNT/$tdir/$tfile

    cancel_lru_locks OSC
    pgcache_empty || return 1

    # 1 stripe on ost2
    lfs setstripe $f $((128 * 1024)) 1 1

    do_facet client cp /etc/termcap $f
    sync
    local osc2_dev=`$LCTL device_list | \
	awk '(/ost2.*client_facet/){print $4}' `
    $LCTL --device %$osc2_dev deactivate
    # my understanding is that there should be nothing in the page
    # cache after the client reconnects?     
    rc=0
    pgcache_empty || rc=2
    $LCTL --device %$osc2_dev activate
    rm -f $f
    return $rc
}
run_test 18a "manual ost invalidate clears page cache immediately"

test_18b() {
# OBD_FAIL_PTLRPC_BULK_PUT_NET|OBD_FAIL_ONCE
    do_facet client mkdir -p $MOUNT/$tdir
    f=$MOUNT/$tdir/$tfile
    f2=$MOUNT/$tdir/${tfile}-2

    cancel_lru_locks OSC
    pgcache_empty || return 1

    # shouldn't have to set stripe size of count==1
    lfs setstripe $f $((128 * 1024)) 0 1
    lfs setstripe $f2 $((128 * 1024)) 0 1

    do_facet client cp /etc/termcap $f
    sync
    # just use this write to trigger the client's eviction from the ost
    sysctl -w lustre.fail_loc=0x80000503
    do_facet client dd if=/dev/zero of=$f2 bs=4k count=1
    sync
    sysctl -w lustre.fail_loc=0
    # allow recovery to complete
    sleep $((TIMEOUT + 2))
    # my understanding is that there should be nothing in the page
    # cache after the client reconnects?     
    rc=0
    pgcache_empty || rc=2
    rm -f $f $f2
    return $rc
}
run_test 18b "eviction and reconnect clears page cache (2766)"

test_19a() {
    f=$MOUNT/$tfile
    do_facet client mcreate $f        || return 1
    drop_ldlm_cancel "chmod 0777 $f"  || echo evicted

    do_facet client checkstat -v -p 0777 $f  || echo evicted
    do_facet client "munlink $f"
}
run_test 19a "test expired_lock_main on mds (2867)"

test_19b() {
    f=$MOUNT/$tfile
    do_facet client multiop $f Ow  || return 1
    do_facet client multiop $f or  || return 2

    cancel_lru_locks OSC

    do_facet client multiop $f or  || return 3
    drop_ldlm_cancel multiop $f Ow  || echo "client evicted, as expected"

    do_facet client munlink $f  || return 4
}
run_test 19b "test expired_lock_main on ost (2867)"

test_20a() {	# bug 2983 - ldlm_handle_enqueue cleanup
	mkdir -p $DIR/$tdir
	multiop $DIR/$tdir/${tfile} O_wc &
	MULTI_PID=$!
	usleep 500
	cancel_lru_locks OSC
#define OBD_FAIL_LDLM_ENQUEUE_EXTENT_ERR 0x308
	do_facet ost sysctl -w lustre.fail_loc=0x80000308
	set -vx
	kill -USR1 $MULTI_PID
	wait $MULTI_PID
	rc=$?
	[ $rc -eq 0 ] && error "multiop didn't fail enqueue: rc $rc" || true
	set +vx
}
run_test 20a "ldlm_handle_enqueue error (should return error)" 

test_20b() {	# bug 2986 - ldlm_handle_enqueue error during open
	mkdir -p $DIR/$tdir
	touch $DIR/$tdir/${tfile}
	cancel_lru_locks OSC
#define OBD_FAIL_LDLM_ENQUEUE_EXTENT_ERR 0x308
	do_facet ost sysctl -w lustre.fail_loc=0x80000308
	dd if=/etc/hosts of=$DIR/$tdir/$tfile && \
		error "didn't fail open enqueue" || true
}
run_test 20b "ldlm_handle_enqueue error (should return error)"

$CLEANUP
