#!/bin/bash

set -e

#         bug  5494 7288 5493
ALWAYS_EXCEPT="24   27   52 $RECOVERY_SMALL_EXCEPT"

PTLDEBUG=${PTLDEBUG:--1}
LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

# also long tests: 19, 21a, 21e, 21f, 23, 27
#                                   1  2.5  2.5    4    4          (min)"
[ "$SLOW" = "no" ] && EXCEPT_SLOW="17  26a  26b    50   51     57"

build_test_filter

# Allow us to override the setup if we already have a mounted system by
# setting SETUP=" " and CLEANUP=" "
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}

cleanup_and_setup_lustre
assert_DIR
rm -rf $DIR/[df][0-9]*

SAMPLE_NAME=recovery-small.junk
SAMPLE_FILE=$TMP/$SAMPLE_NAME
# make this big, else test 9 doesn't wait for bulk -- bz 5595
dd if=/dev/urandom of=$SAMPLE_FILE bs=1M count=4

test_1() {
    drop_request "mcreate $MOUNT/1"  || return 1
    drop_reint_reply "mcreate $MOUNT/2"    || return 2
}
run_test 1 "mcreate: drop req, drop rep"

test_2() {
    drop_request "tchmod 111 $MOUNT/2"  || return 1
    drop_reint_reply "tchmod 666 $MOUNT/2"    || return 2
}
run_test 2 "chmod: drop req, drop rep"

test_3() {
    drop_request "statone $MOUNT/2" || return 1
    drop_reply "statone $MOUNT/2"   || return 2
}
run_test 3 "stat: drop req, drop rep"

test_4() {
    do_facet client "cp /etc/inittab $MOUNT/inittab" || return 1
    drop_request "cat $MOUNT/inittab > /dev/null"   || return 2
    drop_reply "cat $MOUNT/inittab > /dev/null"     || return 3
}
run_test 4 "open: drop req, drop rep"

test_5() {
    drop_request "mv $MOUNT/inittab $MOUNT/renamed" || return 1
    drop_reint_reply "mv $MOUNT/renamed $MOUNT/renamed-again" || return 2
    do_facet client "checkstat -v $MOUNT/renamed-again"  || return 3
}
run_test 5 "rename: drop req, drop rep"

[ ! -e $MOUNT/renamed-again ] && cp /etc/inittab $MOUNT/renamed-again
test_6() {
    drop_request "mlink $MOUNT/renamed-again $MOUNT/link1" || return 1
    drop_reint_reply "mlink $MOUNT/renamed-again $MOUNT/link2"   || return 2
}
run_test 6 "link: drop req, drop rep"

[ ! -e $MOUNT/link1 ] && mlink $MOUNT/renamed-again $MOUNT/link1
[ ! -e $MOUNT/link2 ] && mlink $MOUNT/renamed-again $MOUNT/link2
test_7() {
    drop_request "munlink $MOUNT/link1"   || return 1
    drop_reint_reply "munlink $MOUNT/link2"     || return 2
}
run_test 7 "unlink: drop req, drop rep"

#bug 1423
test_8() {
    drop_reint_reply "touch $MOUNT/$tfile"    || return 1
}
run_test 8 "touch: drop rep (bug 1423)"

#bug 1420
test_9() {
    pause_bulk "cp /etc/profile $MOUNT/$tfile"       || return 1
    do_facet client "cp ${SAMPLE_FILE} $MOUNT/${tfile}.2"  || return 2
    do_facet client "sync"
    do_facet client "rm $MOUNT/$tfile $MOUNT/${tfile}.2" || return 3
}
run_test 9 "pause bulk on OST (bug 1420)"

#bug 1521
test_10() {
    do_facet client mcreate $MOUNT/$tfile        || return 1
    drop_bl_callback "chmod 0777 $MOUNT/$tfile"  || echo "evicted as expected"
    # wait for the mds to evict the client
    #echo "sleep $(($TIMEOUT*2))"
    #sleep $(($TIMEOUT*2))
    do_facet client touch $MOUNT/$tfile || echo "touch failed, evicted"
    do_facet client checkstat -v -p 0777 $MOUNT/$tfile  || return 3
    do_facet client "munlink $MOUNT/$tfile"
}
run_test 10 "finish request on server after client eviction (bug 1521)"

#bug 2460
# wake up a thread waiting for completion after eviction
test_11(){
    do_facet client multiop $MOUNT/$tfile Ow  || return 1
    do_facet client multiop $MOUNT/$tfile or  || return 2

    cancel_lru_locks osc

    do_facet client multiop $MOUNT/$tfile or  || return 3
    drop_bl_callback multiop $MOUNT/$tfile Ow || echo "evicted as expected"

    do_facet client munlink $MOUNT/$tfile  || return 4
}
run_test 11 "wake up a thread waiting for completion after eviction (b=2460)"

#b=2494
test_12(){
    $LCTL mark multiop $MOUNT/$tfile OS_c 
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x115"
    clear_failloc $SINGLEMDS $((TIMEOUT * 2)) &
    multiop_bg_pause $MOUNT/$tfile OS_c || return 1
    PID=$!
#define OBD_FAIL_MDS_CLOSE_NET           0x115
    kill -USR1 $PID
    echo "waiting for multiop $PID"
    wait $PID || return 2
    do_facet client munlink $MOUNT/$tfile  || return 3
}
run_test 12 "recover from timed out resend in ptlrpcd (b=2494)"

# Bug 113, check that readdir lost recv timeout works.
test_13() {
    mkdir $MOUNT/readdir || return 1
    touch $MOUNT/readdir/newentry || return
# OBD_FAIL_MDS_READPAGE_NET|OBD_FAIL_ONCE
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000104"
    ls $MOUNT/readdir || return 3
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"
    rm -rf $MOUNT/readdir || return 4
}
run_test 13 "mdc_readpage restart test (bug 1138)"

# Bug 113, check that readdir lost send timeout works.
test_14() {
    mkdir $MOUNT/readdir
    touch $MOUNT/readdir/newentry
# OBD_FAIL_MDS_SENDPAGE|OBD_FAIL_ONCE
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000106"
    ls $MOUNT/readdir || return 1
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"
}
run_test 14 "mdc_readpage resend test (bug 1138)"

test_15() {
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000128"
    touch $DIR/$tfile && return 1
    return 0
}
run_test 15 "failed open (-ENOMEM)"

READ_AHEAD=`lctl get_param -n llite.*.max_read_ahead_mb | head -n 1`
stop_read_ahead() {
   lctl set_param -n llite.*.max_read_ahead_mb 0
}

start_read_ahead() {
   lctl set_param -n llite.*.max_read_ahead_mb $READ_AHEAD
}

test_16() {
    do_facet client cp /etc/termcap $MOUNT
    sync
    stop_read_ahead

#define OBD_FAIL_PTLRPC_BULK_PUT_NET 0x504 | OBD_FAIL_ONCE
    do_facet ost1 "lctl set_param fail_loc=0x80000504"
    cancel_lru_locks osc
    # OST bulk will time out here, client resends
    do_facet client "cmp /etc/termcap $MOUNT/termcap" || return 1
    do_facet ost1 lctl set_param fail_loc=0
    # give recovery a chance to finish (shouldn't take long)
    sleep $TIMEOUT
    do_facet client "cmp /etc/termcap $MOUNT/termcap" || return 2
    start_read_ahead
}
run_test 16 "timeout bulk put, don't evict client (2732)"

test_17() {
    local at_max_saved=0

    # With adaptive timeouts, bulk_get won't expire until adaptive_timeout_max
    if at_is_valid && at_is_enabled; then
        at_max_saved=$(at_max_get ost1)
        at_max_set $TIMEOUT ost1
    fi

    # OBD_FAIL_PTLRPC_BULK_GET_NET 0x0503 | OBD_FAIL_ONCE
    # OST bulk will time out here, client retries
    do_facet ost1 lctl set_param fail_loc=0x80000503
    # need to ensure we send an RPC
    do_facet client cp /etc/termcap $DIR/$tfile
    sync

    # with AT, client will wait adaptive_max*factor+net_latency before
    # expiring the req, hopefully timeout*2 is enough
    sleep $(($TIMEOUT*2))

    do_facet ost1 lctl set_param fail_loc=0
    do_facet client "df $DIR"
    # expect cmp to succeed, client resent bulk
    do_facet client "cmp /etc/termcap $DIR/$tfile" || return 3
    do_facet client "rm $DIR/$tfile" || return 4
    [ $at_max_saved -ne 0 ] && $(at_max_set $at_max_saved ost1)
    return 0
}
run_test 17 "timeout bulk get, don't evict client (2732)"

test_18a() {
    [ -z ${ost2_svc} ] && skip "needs 2 osts" && return 0

    do_facet client mkdir -p $MOUNT/$tdir
    f=$MOUNT/$tdir/$tfile

    cancel_lru_locks osc
    pgcache_empty || return 1

    # 1 stripe on ost2
    lfs setstripe $f -s $((128 * 1024)) -i 1 -c 1

    do_facet client cp $SAMPLE_FILE $f
    sync
    local osc2dev=`lctl get_param -n devices | grep ${ost2_svc}-osc- | egrep -v 'MDT' | awk '{print $1}'`
    $LCTL --device $osc2dev deactivate || return 3
    # my understanding is that there should be nothing in the page
    # cache after the client reconnects?     
    rc=0
    pgcache_empty || rc=2
    $LCTL --device $osc2dev activate
    rm -f $f
    return $rc
}
run_test 18a "manual ost invalidate clears page cache immediately"

test_18b() {
    do_facet client mkdir -p $MOUNT/$tdir
    f=$MOUNT/$tdir/$tfile
    f2=$MOUNT/$tdir/${tfile}-2

    cancel_lru_locks osc
    pgcache_empty || return 1

    # shouldn't have to set stripe size of count==1
    lfs setstripe $f -s $((128 * 1024)) -i 0 -c 1
    lfs setstripe $f2 -s $((128 * 1024)) -i 0 -c 1

    do_facet client cp $SAMPLE_FILE $f
    sync
    ost_evict_client
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

test_18c() {
    do_facet client mkdir -p $MOUNT/$tdir
    f=$MOUNT/$tdir/$tfile
    f2=$MOUNT/$tdir/${tfile}-2

    cancel_lru_locks osc
    pgcache_empty || return 1

    # shouldn't have to set stripe size of count==1
    lfs setstripe $f -s $((128 * 1024)) -i 0 -c 1
    lfs setstripe $f2 -s $((128 * 1024)) -i 0 -c 1

    do_facet client cp $SAMPLE_FILE $f
    sync
    ost_evict_client

    # OBD_FAIL_OST_CONNECT_NET2
    # lost reply to connect request
    do_facet ost1 lctl set_param fail_loc=0x80000225
    # force reconnect
    df $MOUNT > /dev/null 2>&1
    sleep 2
    # my understanding is that there should be nothing in the page
    # cache after the client reconnects?     
    rc=0
    pgcache_empty || rc=2
    rm -f $f $f2
    return $rc
}
run_test 18c "Dropped connect reply after eviction handing (14755)"

test_19a() {
    f=$MOUNT/$tfile
    do_facet client mcreate $f        || return 1
    drop_ldlm_cancel "chmod 0777 $f"  || echo "evicted as expected"

    do_facet client checkstat -v -p 0777 $f  || echo evicted
    # let the client reconnect
    sleep 5
    do_facet client "munlink $f"
}
run_test 19a "test expired_lock_main on mds (2867)"

test_19b() {
    f=$MOUNT/$tfile
    do_facet client multiop $f Ow  || return 1
    do_facet client multiop $f or  || return 2

    cancel_lru_locks osc

    do_facet client multiop $f or  || return 3
    drop_ldlm_cancel multiop $f Ow  || echo "client evicted, as expected"

    do_facet client munlink $f  || return 4
}
run_test 19b "test expired_lock_main on ost (2867)"

test_20a() {	# bug 2983 - ldlm_handle_enqueue cleanup
	mkdir -p $DIR/$tdir
	lfs setstripe $DIR/$tdir/${tfile} -i 0 -c 1
	multiop_bg_pause $DIR/$tdir/${tfile} O_wc || return 1
	MULTI_PID=$!
	cancel_lru_locks osc
#define OBD_FAIL_LDLM_ENQUEUE_EXTENT_ERR 0x308
	do_facet ost1 lctl set_param fail_loc=0x80000308
	kill -USR1 $MULTI_PID
	wait $MULTI_PID
	rc=$?
	[ $rc -eq 0 ] && error "multiop didn't fail enqueue: rc $rc" || true
}
run_test 20a "ldlm_handle_enqueue error (should return error)" 

test_20b() {	# bug 2986 - ldlm_handle_enqueue error during open
	mkdir -p $DIR/$tdir
	lfs setstripe $DIR/$tdir/${tfile} -i 0 -c 1
	cancel_lru_locks osc
#define OBD_FAIL_LDLM_ENQUEUE_EXTENT_ERR 0x308
	do_facet ost1 lctl set_param fail_loc=0x80000308
	dd if=/etc/hosts of=$DIR/$tdir/$tfile && \
		error "didn't fail open enqueue" || true
}
run_test 20b "ldlm_handle_enqueue error (should return error)"

test_21a() {
       mkdir -p $DIR/$tdir-1
       mkdir -p $DIR/$tdir-2
       multiop_bg_pause $DIR/$tdir-1/f O_c || return 1
       close_pid=$!

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000129"
       multiop $DIR/$tdir-2/f Oc &
       open_pid=$!
       sleep 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000115"
       kill -USR1 $close_pid
       cancel_lru_locks mdc
       wait $close_pid || return 1
       wait $open_pid || return 2
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       $CHECKSTAT -t file $DIR/$tdir-1/f || return 3
       $CHECKSTAT -t file $DIR/$tdir-2/f || return 4

       rm -rf $DIR/$tdir-*
}
run_test 21a "drop close request while close and open are both in flight"

test_21b() {
       mkdir -p $DIR/$tdir-1
       mkdir -p $DIR/$tdir-2
       multiop_bg_pause $DIR/$tdir-1/f O_c || return 1
       close_pid=$!

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000107"
       mcreate $DIR/$tdir-2/f &
       open_pid=$!
       sleep 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       kill -USR1 $close_pid
       cancel_lru_locks mdc
       wait $close_pid || return 1
       wait $open_pid || return 3

       $CHECKSTAT -t file $DIR/$tdir-1/f || return 4
       $CHECKSTAT -t file $DIR/$tdir-2/f || return 5
       rm -rf $DIR/$tdir-*
}
run_test 21b "drop open request while close and open are both in flight"

test_21c() {
       mkdir -p $DIR/$tdir-1
       mkdir -p $DIR/$tdir-2
       multiop_bg_pause $DIR/$tdir-1/f O_c || return 1
       close_pid=$!

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000107"
       mcreate $DIR/$tdir-2/f &
       open_pid=$!
       sleep 3
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000115"
       kill -USR1 $close_pid
       cancel_lru_locks mdc
       wait $close_pid || return 1
       wait $open_pid || return 2

       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       $CHECKSTAT -t file $DIR/$tdir-1/f || return 2
       $CHECKSTAT -t file $DIR/$tdir-2/f || return 3
       rm -rf $DIR/$tdir-*
}
run_test 21c "drop both request while close and open are both in flight"

test_21d() {
       mkdir -p $DIR/$tdir-1
       mkdir -p $DIR/$tdir-2
       multiop_bg_pause $DIR/$tdir-1/f O_c || return 1
       pid=$!

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000129"
       multiop $DIR/$tdir-2/f Oc &
       sleep 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000122"
       kill -USR1 $pid
       cancel_lru_locks mdc
       wait $pid || return 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       $CHECKSTAT -t file $DIR/$tdir-1/f || return 2
       $CHECKSTAT -t file $DIR/$tdir-2/f || return 3

       rm -rf $DIR/$tdir-*
}
run_test 21d "drop close reply while close and open are both in flight"

test_21e() {
       mkdir -p $DIR/$tdir-1
       mkdir -p $DIR/$tdir-2
       multiop_bg_pause $DIR/$tdir-1/f O_c || return 1
       pid=$!

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000119"
       touch $DIR/$tdir-2/f &
       sleep 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       kill -USR1 $pid
       cancel_lru_locks mdc
       wait $pid || return 1

       sleep $TIMEOUT
       $CHECKSTAT -t file $DIR/$tdir-1/f || return 2
       $CHECKSTAT -t file $DIR/$tdir-2/f || return 3
       rm -rf $DIR/$tdir-*
}
run_test 21e "drop open reply while close and open are both in flight"

test_21f() {
       mkdir -p $DIR/$tdir-1
       mkdir -p $DIR/$tdir-2
       multiop_bg_pause $DIR/$tdir-1/f O_c || return 1
       pid=$!

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000119"
       touch $DIR/$tdir-2/f &
       sleep 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000122"
       kill -USR1 $pid
       cancel_lru_locks mdc
       wait $pid || return 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       $CHECKSTAT -t file $DIR/$tdir-1/f || return 2
       $CHECKSTAT -t file $DIR/$tdir-2/f || return 3
       rm -rf $DIR/$tdir-*
}
run_test 21f "drop both reply while close and open are both in flight"

test_21g() {
       mkdir -p $DIR/$tdir-1
       mkdir -p $DIR/$tdir-2
       multiop_bg_pause $DIR/$tdir-1/f O_c || return 1
       pid=$!

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000119"
       touch $DIR/$tdir-2/f &
       sleep 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000115"
       kill -USR1 $pid
       cancel_lru_locks mdc
       wait $pid || return 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       $CHECKSTAT -t file $DIR/$tdir-1/f || return 2
       $CHECKSTAT -t file $DIR/$tdir-2/f || return 3
       rm -rf $DIR/$tdir-*
}
run_test 21g "drop open reply and close request while close and open are both in flight"

test_21h() {
       mkdir -p $DIR/$tdir-1
       mkdir -p $DIR/$tdir-2
       multiop_bg_pause $DIR/$tdir-1/f O_c || return 1
       pid=$!

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000107"
       touch $DIR/$tdir-2/f &
       touch_pid=$!
       sleep 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000122"
       cancel_lru_locks mdc
       kill -USR1 $pid
       wait $pid || return 1
       do_facet $SINGLEMDS "lctl set_param fail_loc=0"

       wait $touch_pid || return 2

       $CHECKSTAT -t file $DIR/$tdir-1/f || return 3
       $CHECKSTAT -t file $DIR/$tdir-2/f || return 4
       rm -rf $DIR/$tdir-*
}
run_test 21h "drop open request and close reply while close and open are both in flight"

# bug 3462 - multiple MDC requests
test_22() {
    f1=$DIR/${tfile}-1
    f2=$DIR/${tfile}-2
    
    do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000115"
    multiop $f2 Oc &
    close_pid=$!

    sleep 1
    multiop $f1 msu || return 1

    cancel_lru_locks mdc
    do_facet $SINGLEMDS "lctl set_param fail_loc=0"

    wait $close_pid || return 2
    rm -rf $f2 || return 4
}
run_test 22 "drop close request and do mknod"

test_23() { #b=4561
    multiop_bg_pause $DIR/$tfile O_c || return 1
    pid=$!
    # give a chance for open
    sleep 5

    # try the close
    drop_request "kill -USR1 $pid"

    fail $SINGLEMDS
    wait $pid || return 1
    return 0
}
run_test 23 "client hang when close a file after mds crash"

test_24() { # bug 11710 details correct fsync() behavior
	mkdir -p $DIR/$tdir
	lfs setstripe $DIR/$tdir -s 0 -i 0 -c 1
	cancel_lru_locks osc
	multiop_bg_pause $DIR/$tdir/$tfile Owy_wyc || return 1
	MULTI_PID=$!
	ost_evict_client
	kill -USR1 $MULTI_PID
	wait $MULTI_PID
	rc=$?
	lctl set_param fail_loc=0x0
	client_reconnect
	[ $rc -eq 0 ] && error_ignore 5494 "multiop didn't fail fsync: rc $rc" || true
}
run_test 24 "fsync error (should return error)"

test_26a() {      # was test_26 bug 5921 - evict dead exports by pinger
# this test can only run from a client on a separate node.
	remote_ost || { skip "local OST" && return 0; }
	remote_mds || { skip "local MDS" && return 0; }
	OST_FILE=obdfilter.${ost1_svc}.num_exports
        OST_EXP="`do_facet ost1 lctl get_param -n $OST_FILE`"
	OST_NEXP1=`echo $OST_EXP | cut -d' ' -f2`
	echo starting with $OST_NEXP1 OST exports
# OBD_FAIL_PTLRPC_DROP_RPC 0x505
	do_facet client lctl set_param fail_loc=0x505
        # evictor takes PING_EVICT_TIMEOUT + 3 * PING_INTERVAL to evict.
        # But if there's a race to start the evictor from various obds,
        # the loser might have to wait for the next ping.
	echo Waiting for $(($TIMEOUT * 8)) secs
	sleep $(($TIMEOUT * 8))
        OST_EXP="`do_facet ost1 lctl get_param -n $OST_FILE`"
	OST_NEXP2=`echo $OST_EXP | cut -d' ' -f2`
	echo ending with $OST_NEXP2 OST exports
	do_facet client lctl set_param fail_loc=0x0
        [ $OST_NEXP1 -le $OST_NEXP2 ] && error "client not evicted"
	return 0
}
run_test 26a "evict dead exports"

test_26b() {      # bug 10140 - evict dead exports by pinger
	client_df
        zconf_mount `hostname` $MOUNT2 || error "Failed to mount $MOUNT2"
        sleep 1 # wait connections being established
	MDS_FILE=mdt.${mds1_svc}.num_exports
        MDS_NEXP1="`do_facet $SINGLEMDS lctl get_param -n $MDS_FILE | cut -d' ' -f2`"
        OST_FILE=obdfilter.${ost1_svc}.num_exports
        OST_NEXP1="`do_facet ost1 lctl get_param -n $OST_FILE | cut -d' ' -f2`"
        echo starting with $OST_NEXP1 OST and $MDS_NEXP1 MDS exports
        zconf_umount `hostname` $MOUNT2 -f
        # evictor takes PING_EVICT_TIMEOUT + 3 * PING_INTERVAL to evict.  
        # But if there's a race to start the evictor from various obds, 
        # the loser might have to wait for the next ping.
        echo Waiting for $(($TIMEOUT * 3)) secs
        sleep $(($TIMEOUT * 3))
        OST_NEXP2="`do_facet ost1 lctl get_param -n $OST_FILE | cut -d' ' -f2`"
        MDS_NEXP2="`do_facet $SINGLEMDS lctl get_param -n $MDS_FILE | cut -d' ' -f2`"
        echo ending with $OST_NEXP2 OST and $MDS_NEXP2 MDS exports
        [ $OST_NEXP1 -le $OST_NEXP2 ] && error "client not evicted from OST"
        [ $MDS_NEXP1 -le $MDS_NEXP2 ] && error "client not evicted from MDS"
	return 0
}
run_test 26b "evict dead exports"

test_27() {
	remote_mds && { skip "remote MDS" && return 0; }
	mkdir -p $DIR/$tdir
	writemany -q -a $DIR/$tdir/$tfile 0 5 &
	CLIENT_PID=$!
	sleep 1
	FAILURE_MODE="SOFT"
	facet_failover $SINGLEMDS
#define OBD_FAIL_OSC_SHUTDOWN            0x407
	lctl set_param fail_loc=0x80000407
	# need to wait for reconnect
	echo -n waiting for fail_loc
	while [ `lctl get_param -n fail_loc` -eq -2147482617 ]; do
	    sleep 1
	    echo -n .
	done
	facet_failover $SINGLEMDS
	#no crashes allowed!
        kill -USR1 $CLIENT_PID
	wait $CLIENT_PID 
	true
}
run_test 27 "fail LOV while using OSC's"

test_28() {      # bug 6086 - error adding new clients
	do_facet client mcreate $MOUNT/$tfile       || return 1
	drop_bl_callback "chmod 0777 $MOUNT/$tfile" ||echo "evicted as expected"
	#define OBD_FAIL_MDS_CLIENT_ADD 0x12f
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000012f"
	# fail once (evicted), reconnect fail (fail_loc), ok
	df || (sleep 10; df) || (sleep 10; df) || error "reconnect failed"
	rm -f $MOUNT/$tfile
	fail $SINGLEMDS		# verify MDS last_rcvd can be loaded
}
run_test 28 "handle error adding new clients (bug 6086)"

test_50() {
	mkdir -p $DIR/$tdir
	# put a load of file creates/writes/deletes
	writemany -q $DIR/$tdir/$tfile 0 5 &
	CLIENT_PID=$!
	echo writemany pid $CLIENT_PID
	sleep 10
	FAILURE_MODE="SOFT"
	fail $SINGLEMDS
	# wait for client to reconnect to MDS
	sleep 60
	fail $SINGLEMDS
	sleep 60
	fail $SINGLEMDS
	# client process should see no problems even though MDS went down
	sleep $TIMEOUT
        kill -USR1 $CLIENT_PID
	wait $CLIENT_PID 
	rc=$?
	echo writemany returned $rc
	#these may fail because of eviction due to slow AST response.
	[ $rc -eq 0 ] || error_ignore 13652 "writemany returned rc $rc" || true
}
run_test 50 "failover MDS under load"

test_51() {
	mkdir -p $DIR/$tdir
	# put a load of file creates/writes/deletes
	writemany -q $DIR/$tdir/$tfile 0 5 &
	CLIENT_PID=$!
	sleep 1
	FAILURE_MODE="SOFT"
	facet_failover $SINGLEMDS
	# failover at various points during recovery
	SEQ="1 5 10 $(seq $TIMEOUT 5 $(($TIMEOUT+10)))"
        echo will failover at $SEQ
        for i in $SEQ
          do
          echo failover in $i sec
          sleep $i
          facet_failover $SINGLEMDS
        done
	# client process should see no problems even though MDS went down
	# and recovery was interrupted
	sleep $TIMEOUT
        kill -USR1 $CLIENT_PID
	wait $CLIENT_PID 
	rc=$?
	echo writemany returned $rc
	[ $rc -eq 0 ] || error_ignore 13652 "writemany returned rc $rc" || true
}
run_test 51 "failover MDS during recovery"

test_52_guts() {
	do_facet client "mkdir -p $DIR/$tdir"
	do_facet client "writemany -q -a $DIR/$tdir/$tfile 300 5" &
	CLIENT_PID=$!
	echo writemany pid $CLIENT_PID
	sleep 10
	FAILURE_MODE="SOFT"
	fail ost1
	rc=0
	wait $CLIENT_PID || rc=$?
	# active client process should see an EIO for down OST
	[ $rc -eq 5 ] && { echo "writemany correctly failed $rc" && return 0; }
	# but timing or failover setup may allow success
	[ $rc -eq 0 ] && { echo "writemany succeeded" && return 0; }
	echo "writemany returned $rc"
	return $rc
}

test_52() {
	mkdir -p $DIR/$tdir
	test_52_guts
	rc=$?
	[ $rc -ne 0 ] && { return $rc; }
	# wait for client to reconnect to OST
	sleep 30
	test_52_guts
	rc=$?
	[ $rc -ne 0 ] && { return $rc; }
	sleep 30
	test_52_guts
	rc=$?
	client_reconnect
	#return $rc
}
run_test 52 "failover OST under load"

# test of open reconstruct
test_53() {
	touch $DIR/$tfile
	drop_ldlm_reply "openfile -f O_RDWR:O_CREAT -m 0755 $DIR/$tfile" ||\
		return 2
}
run_test 53 "touch: drop rep"

test_54() {
	zconf_mount `hostname` $MOUNT2
        touch $DIR/$tfile
        touch $DIR2/$tfile.1
        sleep 10
        cat $DIR2/$tfile.missing # save transno = 0, rc != 0 into last_rcvd
        fail $SINGLEMDS
        umount $MOUNT2
        ERROR=`dmesg | egrep "(test 54|went back in time)" | tail -n1 | grep "went back in time"`
        [ x"$ERROR" == x ] || error "back in time occured"
}
run_test 54 "back in time"

# bug 11330 - liblustre application death during I/O locks up OST
test_55() {
	remote_ost && { skip "remote OST" && return 0; }

	mkdir -p $DIR/$tdir

	# first dd should be finished quickly
	dd if=/dev/zero of=$DIR/$tdir/$tfile-1 bs=32M count=4  &
	DDPID=$!
	count=0
	echo  "step1: testing ......"
	while [ true ]; do
	    if [ -z `ps x | awk '$1 == '$DDPID' { print $5 }'` ]; then break; fi
	    count=$[count+1]
	    if [ $count -gt 64 ]; then
		error "dd should be finished!"
	    fi
	    sleep 1
	done	
	echo "(dd_pid=$DDPID, time=$count)successful"

        #define OBD_FAIL_OST_DROP_REQ            0x21d
	do_facet ost lctl set_param fail_loc=0x0000021d
	# second dd will be never finished
	dd if=/dev/zero of=$DIR/$tdir/$tfile-2 bs=32M count=4  &	
	DDPID=$!
	count=0
	echo  "step2: testing ......"
	while [ $count -le 64 ]; do
	    dd_name="`ps x | awk '$1 == '$DDPID' { print $5 }'`"	    
	    if [ -z  $dd_name ]; then 
                ls -l $DIR/$tdir
		echo  "debug: (dd_name=$dd_name, dd_pid=$DDPID, time=$count)"
		error "dd shouldn't be finished!"
	    fi
	    count=$[count+1]
	    sleep 1
	done	
	echo "(dd_pid=$DDPID, time=$count)successful"

	#Recover fail_loc and dd will finish soon
	do_facet ost lctl set_param fail_loc=0
	count=0
	echo  "step3: testing ......"
	while [ true ]; do
	    if [ -z `ps x | awk '$1 == '$DDPID' { print $5 }'` ]; then break; fi
	    count=$[count+1]
	    if [ $count -gt 500 ]; then
		error "dd should be finished!"
	    fi
	    sleep 1
	done	
	echo "(dd_pid=$DDPID, time=$count)successful"

        rm -rf $DIR/$tdir
}
run_test 55 "ost_brw_read/write drops timed-out read/write request"

test_56() { # b=11277
#define OBD_FAIL_MDS_RESEND      0x136
        touch $DIR/$tfile
        do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000136"
        stat $DIR/$tfile
        do_facet $SINGLEMDS "lctl set_param fail_loc=0"
        rm -f $DIR/$tfile
}
run_test 56 "do not allow reconnect to busy exports"

test_57_helper() {
        # no oscs means no client or mdt 
        while lctl get_param osc.*.* > /dev/null 2>&1; do
                : # loop until proc file is removed
        done
}

test_57() { # bug 10866
        test_57_helper &
        pid=$!
        sleep 1
#define OBD_FAIL_LPROC_REMOVE            0xB00
        lctl set_param fail_loc=0x80000B00
        zconf_umount `hostname` $DIR
        lctl set_param fail_loc=0x80000B00
        fail_abort $SINGLEMDS
        kill -9 $pid
        lctl set_param fail_loc=0
        mount_client $DIR
        do_facet client "df $DIR"
}
run_test 57 "read procfs entries causes kernel crash"

test_58() { # bug 11546
#define OBD_FAIL_MDC_ENQUEUE_PAUSE        0x801
        touch $MOUNT/$tfile
        ls -la $MOUNT/$tfile
        lctl set_param fail_loc=0x80000801
        cp $MOUNT/$tfile /dev/null &
        pid=$!
        sleep 1
        lctl set_param fail_loc=0
        drop_bl_callback rm -f $MOUNT/$tfile
        wait $pid
        do_facet client "df $DIR"
}
run_test 58 "Eviction in the middle of open RPC reply processing"

test_59() { # bug 10589
	zconf_mount `hostname` $MOUNT2 || error "Failed to mount $MOUNT2"
	echo $DIR2 | grep -q $MOUNT2 || error "DIR2 is not set properly: $DIR2"
#define OBD_FAIL_LDLM_CANCEL_EVICT_RACE  0x311
	lctl set_param fail_loc=0x311
	writes=$(LANG=C dd if=/dev/zero of=$DIR2/$tfile count=1 2>&1)
	[ $? = 0 ] || error "dd write failed"
	writes=$(echo $writes | awk  -F '+' '/out/ {print $1}')
	lctl set_param fail_loc=0
	sync
	zconf_umount `hostname` $MOUNT2 -f
	reads=$(LANG=C dd if=$DIR/$tfile of=/dev/null 2>&1)
	[ $? = 0 ] || error "dd read failed"
	reads=$(echo $reads | awk -F '+' '/in/ {print $1}')
	[ "$reads" -eq "$writes" ] || error "read" $reads "blocks, must be" $writes
}
run_test 59 "Read cancel race on client eviction"

equals_msg `basename $0`: test complete, cleaning up
check_and_cleanup_lustre
[ -f "$TESTSUITELOG" ] && cat $TESTSUITELOG || true
