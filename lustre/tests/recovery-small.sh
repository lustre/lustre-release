#!/bin/bash

set -e

PTLDEBUG=${PTLDEBUG:--1}
LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"
init_logging

ALWAYS_EXCEPT="$RECOVERY_SMALL_EXCEPT "

if $SHARED_KEY; then
	always_except LU-17141 133
fi

build_test_filter

require_dsh_mds || exit 0

# Allow us to override the setup if we already have a mounted system by
# setting SETUP=" " and CLEANUP=" "
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}

check_and_setup_lustre

assert_DIR
rm -rf $DIR/d[0-9]* $DIR/f.${TESTSUITE}*

# new sequence needed for MDS < v2_15_61-226-gf00d2467fc
if (( $MDS1_VERSION < $(version_code 2.15.61.226) )); then
	force_new_seq_all
fi

test_1() {
	local f1="$DIR/$tfile"
	local f2="$DIR/$tfile.2"

	drop_request "mcreate $f1" ||
		error_noexit "create '$f1': drop req"

	drop_reint_reply "mcreate $f2" ||
		error_noexit "create '$f2': drop rep"

	drop_request "tchmod 111 $f2" ||
		error_noexit "chmod '$f2': drop req"

	drop_reint_reply "tchmod 666 $f2" ||
		error_noexit "chmod '$f2': drop rep"

	drop_request "statone $f2" ||
		error_noexit "stat '$f2': drop req"

	drop_reply  "statone $f2" ||
		error_noexit "stat '$f2': drop rep"
}
run_test 1 "create, chmod, stat: drop req, drop rep"

test_4() {
	local t=$DIR/$tfile
	do_facet_create_file client $t 10K ||
		error_noexit "Create file $t"

	drop_request "cat $t > /dev/null" ||
		error_noexit "Open request for $t file"

	drop_reply "cat $t > /dev/null" ||
		error_noexit "Open replay for $t file"
}
run_test 4 "open: drop req, drop rep"

test_5() {
	local T=$DIR/$tfile
	local R="$T-renamed"
	local RR="$T-renamed-again"
	do_facet_create_file client $T 10K ||
		error_noexit "Create file $T"

	drop_request "mv $T $R" ||
		error_noexit "Rename $T"

	drop_reint_reply "mv $R $RR" ||
		error_noexit "Failed rename replay on $R"

	do_facet client "checkstat -v $RR" ||
		error_noexit "checkstat error on $RR"

	do_facet client "rm $RR" ||
		error_noexit "Can't remove file $RR"
}
run_test 5 "rename: drop req, drop rep"

test_6() {
	local T=$DIR/$tfile
	local LINK1=$DIR/$tfile.link1
	local LINK2=$DIR/$tfile.link2

	do_facet_create_file client $T 10K || error_noexit "Create file $T"
	drop_request "link $T $LINK1" || error_noexit "link request for $T"
	drop_reint_reply "link $T $LINK2" || error_noexit "link reply for $T"
	drop_request "unlink $LINK1" || error_noexit "unlink request for $T"
	drop_reint_reply "unlink $LINK2" || error_noexit "unlink reply for $T"
	do_facet client "rm $T" || error_noexit "Can't remove file $T"
}
run_test 6 "link, unlink: drop req, drop rep"

#bug 1423
test_8() {
	drop_reint_reply "touch $DIR/$tfile"    || return 1
}
run_test 8 "touch: drop rep (bug 1423)"

#bug 1420
test_9() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	local t1=${tfile}.1
	local t2=${tfile}.2
	do_facet_random_file client $TMP/$tfile 1K ||
		error_noexit "Create random file $TMP/$tfile"
	# make this big, else test 9 doesn't wait for bulk -- bz 5595
	do_facet_create_file client $TMP/$t1 4M ||
		error_noexit "Create file $TMP/$t1"
	do_facet client "cp $TMP/$t1 $DIR/$t1" ||
		error_noexit "Can't copy to $DIR/$t1 file"
	pause_bulk "cp $TMP/$tfile $DIR/$tfile" ||
		error_noexit "Can't pause_bulk copy"
	do_facet client "cp $TMP/$t1 $DIR/$t2" ||
		error_noexit "Can't copy file"
	do_facet client "sync"
	do_facet client "rm $DIR/$tfile $DIR/$t2 $DIR/$t1" ||
		error_noexit "Can't remove files"
	do_facet client "rm $TMP/$t1 $TMP/$tfile"
}
run_test 9 "pause bulk on OST (bug 1420)"

#bug 1521
test_10a() {
	local before=$(date +%s)
	local evict
	local lru_param="ldlm.namespaces.*mdc*.lru_max_age"
	local old_max_age=($($LCTL get_param -n $lru_param))
	local old_ratelimit=$($LCTL get_param console_ratelimit)

	$LCTL set_param $lru_param=3900s console_ratelimit=0
	stack_trap "$LCTL set_param $lru_param=$old_max_age $old_ratelimit"

	do_facet client "stat $DIR > /dev/null"  ||
		error "failed to stat $DIR: $?"
	drop_bl_callback "chmod 0777 $DIR" ||
		error "failed to chmod $DIR: $?"

	# let the client reconnect
	client_reconnect
	evict=$(do_facet client $LCTL get_param mdc.$FSNAME-MDT*.state |
	  awk -F"[ [,]" '/EVICTED ]$/ { if (mx<$5) {mx=$5;} } END { print mx }')
	[[ -n "$evict" ]] && (( $evict > $before )) ||
		(do_facet client $LCTL get_param mdc.$FSNAME-MDT*.state;
		    error "no eviction: $evict before:$before")

	do_facet client checkstat -v -p 0777 $DIR ||
		error "client checkstat failed: $?"

	# console messages may be ratelimited on later iterations
	(( ONLY_REPEAT_ITER == 1 )) || return 0

	# check that the thread watchdog is working properly
	do_facet mds1 dmesg | tac | sed "/${TESTNAME/_/ }/,$ d" |
		grep "[Ss]ervice thread pid .* was inactive" ||
		error "no service thread inactive message for ${TESTNAME/_/ }"

	# can't check for "completed" message where it was removed
	(( $MDS1_VERSION > $(version_code v2_12_50-83-gfc9de679a4) &&
	   $MDS1_VERSION < $(version_code 2.15.62.59) )) ||
		do_facet mds1 dmesg | tac | sed "/${TESTNAME/_/ }/,$ d" |
			grep "[Ss]ervice thread pid .* completed after" ||
		error "no service thread completed  message for ${TESTNAME/_/ }"
}
run_test 10a "finish request on server after client eviction (bug 1521)"

test_10b() {
	local before=$(date +%s)
	local evict

	[[ "$MDS1_VERSION" -lt $(version_code 2.6.53) ]] &&
		skip "Need MDS version at least 2.6.53"
	do_facet client "stat $DIR > /dev/null"  ||
		error "failed to stat $DIR: $?"
	drop_bl_callback_once "chmod 0777 $DIR" ||
		error "failed to chmod $DIR: $?"

	# let the client reconnect
	client_reconnect
	evict=$(do_facet client $LCTL get_param mdc.$FSNAME-MDT*.state |
	  awk -F"[ [,]" '/EVICTED ]$/ { if (mx<$5) {mx=$5;} } END { print mx }')

	[ -z "$evict" ] || [[ $evict -le $before ]] ||
		(do_facet client $LCTL get_param mdc.$FSNAME-MDT*.state;
		    error "eviction happened: $evict before:$before")

	do_facet client checkstat -v -p 0777 $DIR ||
 		error "client checkstat failed: $?"
}
run_test 10b "re-send BL AST"

test_10c() {
	local before=$(date +%s)
	local evict
	local mdccli
	local mdcpath
	local conn_uuid
	local workdir
	local pid
	local rc

	workdir="${DIR}/${tdir}"
	mkdir -p ${workdir} || error "can't create workdir $?"
	stat ${workdir} > /dev/null ||
		error "failed to stat ${workdir}: $?"
	mdtidx=$($LFS getdirstripe -i ${workdir})
	mdtname=$($LFS mdts ${workdir} | grep -e "^$mdtidx:" |
		  awk '{sub("_UUID", "", $2); print $2;}')
	#assume one client
	mdccli=$($LCTL dl | grep "${mdtname}-mdc" | awk '{print $4;}')
	conn_uuid=$($LCTL get_param -n mdc.${mdccli}.conn_uuid)
	mdcpath="mdc.${mdccli}.import=connection=${conn_uuid}"

	drop_bl_callback_once "chmod 0777 ${workdir}" &
	pid=$!

	# let chmod blocked
	sleep 1
	# force client reconnect
	$LCTL set_param "${mdcpath}"

	# wait client reconnect
	client_reconnect
	wait $pid
	rc=$?
	evict=$($LCTL get_param mdc.${mdccli}.state |
	   awk -F"[ [,]" '/EVICTED]$/ { if (t<$4) {t=$4;} } END { print t }')

	[[ $evict -le $before ]] ||
		( $LCTL get_param mdc.$FSNAME-MDT*.state;
		    error "eviction happened: $EVICT before:$BEFORE" )

	[ $rc -eq 0 ] || error "chmod must finished OK"
	checkstat -v -p 0777 "${workdir}" ||
		error "client checkstat failed: $?"
}
run_test 10c "re-send BL AST vs reconnect race (LU-5569)"

test_10d() {
	local before=$(date +%s)
	local evict

	[[ "$MDS1_VERSION" -lt $(version_code 2.6.90) ]] &&
		skip "Need MDS version at least 2.6.90"

	# sleep 1 is to make sure that BEFORE is not equal to EVICTED below
	sleep 1
	rm -f $TMP/$tfile
	echo -n ", world" | dd of=$TMP/$tfile bs=1c seek=5

	remount_client $MOUNT
	mount_client $MOUNT2

	cancel_lru_locks osc
	$LFS setstripe -i 0 -c 1 $DIR1/$tfile
	echo -n hello | dd of=$DIR1/$tfile bs=5

	stat $DIR2/$tfile >& /dev/null
	$LCTL set_param fail_err=71
	drop_bl_callback "echo -n \\\", world\\\" >> $DIR2/$tfile"

	client_reconnect

	cancel_lru_locks osc
	cmp -l $DIR1/$tfile $DIR2/$tfile || error "file contents differ"
	cmp -l $DIR1/$tfile $TMP/$tfile || error "wrong content found"

	evict=$(do_facet client $LCTL get_param osc.$FSNAME-OST0000*.state | \
		tr -d '\-\[\] ' | \
	  awk -F"[ [,]" '/EVICTED$/ { if (mx<$1) {mx=$1;} } END { print mx }')

	[[ $evict -gt $before ]] ||
		(do_facet client $LCTL get_param osc.$FSNAME-OST0000*.state;
		    error "no eviction: $evict before:$before")

	$LCTL set_param fail_err=0
	rm $TMP/$tfile
	umount_client $MOUNT2
}
run_test 10d "test failed blocking ast"

test_10e()
{
	[[ "$OST1_VERSION" -le $(version_code 2.8.58) ]] &&
		skip "Need OST version at least 2.8.59"
	[ $CLIENTCOUNT -lt 2 ] && skip "need two clients"
	[ $(facet_host client) == $(facet_host ost1) ] &&
		skip "need ost1 and client on different nodes"
	local -a clients=(${CLIENTS//,/ })
	local client1=${clients[0]}
	local client2=${clients[1]}

	$LFS setstripe -c 1 -i 0 $DIR/$tfile-1 $DIR/$tfile-2
	$MULTIOP $DIR/$tfile-1 Ow1048576c

#define OBD_FAIL_LDLM_BL_CALLBACK_NET                   0x305
	$LCTL set_param fail_loc=0x80000305

#define OBD_FAIL_LDLM_ENQUEUE_OLD_EXPORT 0x30e
	do_facet ost1 "$LCTL set_param fail_loc=0x1000030e"
	# hit OBD_FAIL_LDLM_ENQUEUE_OLD_EXPORT twice:
	# 1. to return ENOTCONN from ldlm_handle_enqueue0
	# 2. to pause reconnect handling between resend and setting
	# import to LUSTRE_IMP_FULL state
	do_facet ost1 "$LCTL set_param fail_val=3"

	# client1 fails ro respond to bl ast
	do_node $client2 "$MULTIOP $DIR/$tfile-1 Ow1048576c" &
	MULTIPID=$!

	# ost1 returns error on enqueue, which causes client1 to reconnect
	do_node $client1 "$MULTIOP $DIR/$tfile-2 Ow1048576c" ||
		error "multiop failed"
	wait $MULTIPID

	do_facet ost1 "$LCTL set_param fail_loc=0"
	do_facet ost1 "$LCTL set_param fail_val=0"
}
run_test 10e "re-send BL AST vs reconnect race 2"

#bug 2460
# wake up a thread waiting for completion after eviction
test_11(){
	do_facet client $MULTIOP $DIR/$tfile Ow  ||
		{ error "multiop write failed: $?"; return 1; }
	do_facet client $MULTIOP $DIR/$tfile or  ||
		{ error "multiop read failed: $?"; return 2; }

	cancel_lru_locks osc

	do_facet client $MULTIOP $DIR/$tfile or  ||
		{ error "multiop read failed: $?"; return 3; }
	drop_bl_callback_once $MULTIOP $DIR/$tfile Ow ||
		echo "evicted as expected"

	do_facet client unlink $DIR/$tfile ||
		{ error "unlink failed: $?"; return 4; }
	# allow recovery to complete
	client_up || client_up || sleep $TIMEOUT
}
run_test 11 "wake up a thread waiting for completion after eviction (b=2460)"

#b=2494
test_12(){
	$LCTL mark $MULTIOP $DIR/$tfile OS_c
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x115"
	clear_failloc $SINGLEMDS $((TIMEOUT * 2)) &
	multiop_bg_pause $DIR/$tfile OS_c ||
		{ error "multiop failed: $?"; return 1; }
	PID=$!
#define OBD_FAIL_MDS_CLOSE_NET           0x115
	kill -USR1 $PID
	echo "waiting for multiop $PID"
	wait $PID || { error "wait for multiop faile: $?"; return 2; }
	do_facet client unlink $DIR/$tfile ||
		{ error "client unlink failed: $?"; return 3; }
	# allow recovery to complete
	client_up || client_up || sleep $TIMEOUT
}
run_test 12 "recover from timed out resend in ptlrpcd (b=2494)"

# Bug 113, check that readdir lost recv timeout works.
test_13() {
	mkdir_on_mdt0 $DIR/$tdir || { error "mkdir failed: $?"; return 1; }
	touch $DIR/$tdir/newentry || { error "touch failed: $?"; return 2; }
# OBD_FAIL_MDS_READPAGE_NET|CFS_FAIL_ONCE
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000104"
	ls $DIR/$tdir || { error "ls failed: $?"; return 3; }
	do_facet $SINGLEMDS "lctl set_param fail_loc=0"
	rm -rf $DIR/$tdir || { error "remove test dir failed: $?"; return 4; }
}
run_test 13 "mdc_readpage restart test (bug 1138)"

# Bug 113, check that readdir lost send timeout works.
test_14() {
	mkdir_on_mdt0 $DIR/$tdir
	touch $DIR/$tdir/newentry
# OBD_FAIL_MDS_SENDPAGE|CFS_FAIL_ONCE
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000106"
	ls $DIR/$tdir || return 1
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
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	do_facet_random_file client $TMP/$tfile 100K ||
		{ error_noexit "Create random file $TMP/$T" ; return 0; }
	do_facet client "cp $TMP/$tfile $DIR/$tfile" ||
		{ error_noexit "Copy to $DIR/$tfile file" ; return 0; }
	sync
	stop_read_ahead

#define OBD_FAIL_PTLRPC_BULK_PUT_NET 0x504 | CFS_FAIL_ONCE
	do_facet ost1 "lctl set_param fail_loc=0x80000504"
	cancel_lru_locks osc
	# OST bulk will time out here, client resends
	do_facet client "cmp $TMP/$tfile $DIR/$tfile" || return 1
	do_facet ost1 lctl set_param fail_loc=0
	# give recovery a chance to finish (shouldn't take long)
	sleep $TIMEOUT
	do_facet client "cmp $TMP/$tfile $DIR/$tfile" || return 2
	start_read_ahead
	rm -f $TMP/$tfile
}
run_test 16 "timeout bulk put, don't evict client (2732)"

test_17a() {
	local at_max_saved=0

	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	local SAMPLE_FILE=$TMP/$tfile
	do_facet_random_file client $SAMPLE_FILE 20K ||
		{ error_noexit "Create random file $SAMPLE_FILE" ; return 0; }

	# With adaptive timeouts, bulk_get won't expire until
	# adaptive_timeout_max
	if at_is_enabled; then
		at_max_saved=$(at_max_get ost1)
		at_max_set $TIMEOUT ost1
	fi

	# OBD_FAIL_PTLRPC_BULK_GET_NET 0x0503 | CFS_FAIL_ONCE
	# OST bulk will time out here, client retries
	do_facet ost1 lctl set_param fail_loc=0x80000503
	# need to ensure we send an RPC
	do_facet client cp $SAMPLE_FILE $DIR/$tfile
	sync

	# with AT, client will wait adaptive_max*factor+net_latency before
	# expiring the req, hopefully timeout*2 is enough
	sleep $(($TIMEOUT*2))

	do_facet ost1 lctl set_param fail_loc=0
	do_facet client "df $DIR"
	# expect cmp to succeed, client resent bulk
	do_facet client "cmp $SAMPLE_FILE $DIR/$tfile" || return 3
	do_facet client "rm $DIR/$tfile" || return 4
	[ $at_max_saved -ne 0 ] && at_max_set $at_max_saved ost1
	return 0
}
run_test 17a "timeout bulk get, don't evict client (2732)"

test_17b() {
	[ -z "$RCLIENTS" ] && skip "Needs multiple clients" && return 0

	# get one of the clients from client list
	local rcli=$(echo $RCLIENTS | cut -d ' ' -f 1)
	local p="$TMP/$TESTSUITE-$TESTNAME.parameters"
	local ldlm_enqueue_min=$(do_facet ost1 find /sys -name ldlm_enqueue_min)
	[ -z "$ldlm_enqueue_min" ] &&
		skip "missing /sys/.../ldlm_enqueue_min" && return 0

	$LFS setstripe -i 0 -c 1 -S 1048576 $DIR/$tfile ||
		error "setstripe failed"
	$LFS setstripe -i 0 -c 1 -S 1048576 $DIR/${tfile}2 ||
		error "setstripe 2 failed"

	save_lustre_params ost1 "at_history" > $p
	save_lustre_params ost1 "bulk_timeout" >> $p
	local dev="${FSNAME}-OST0000"
	save_lustre_params ost1 "obdfilter.$dev.brw_size" >> $p
	local ldlm_enqueue_min_save=$(do_facet ost1 cat $ldlm_enqueue_min)

	local new_at_history=15

	do_facet ost1 "$LCTL set_param at_history=$new_at_history"
	do_facet ost1 "$LCTL set_param bulk_timeout=30"
	do_facet ost1 "echo 30 > /sys/module/ptlrpc/parameters/ldlm_enqueue_min"

	# brw_size is required to be 4m so that bulk transfer timeout
	# could be simulated with OBD_FAIL_PTLRPC_CLIENT_BULK_CB3
	local brw_size=$($LCTL get_param -n \
	    osc.$FSNAME-OST0000-osc-[^M]*.import |
	    awk '/max_brw_size/{print $2}')
	if [ $brw_size -ne 4194304 ]
	then
		save_lustre_params ost1 "obdfilter.$dev.brw_size" >> $p
		do_facet ost1 "$LCTL set_param obdfilter.$dev.brw_size=4"
		remount_client $MOUNT
	fi

	# get service estimate expanded
	#define OBD_FAIL_OST_BRW_PAUSE_PACK		 0x224
	do_facet ost1 "$LCTL set_param fail_loc=0x80000224 fail_val=35"
	echo "delay rpc servicing by 35 seconds"
	dd if=/dev/zero of=$DIR/$tfile bs=1M count=1 conv=fdatasync

	local estimate
	estimate=$($LCTL get_param -n osc.$dev-osc-*.timeouts |
	    awk '/portal 6/ {print $5}')
	echo "service estimates increased to $estimate"

	# let current worst service estimate to get closer to obliteration
	sleep $((new_at_history / 3))

	# start i/o and simulate bulk transfer loss
	#define OBD_FAIL_PTLRPC_CLIENT_BULK_CB3     0x520
	do_facet ost1 "$LCTL set_param fail_loc=0xa0000520 fail_val=1"
	dd if=/dev/zero of=$DIR/$tfile bs=2M count=1 conv=fdatasync,notrunc &
	local writedd=$!

	# start lock conflict handling
	sleep $((new_at_history / 3))
	do_node $rcli "dd if=$DIR/$tfile of=/dev/null bs=1M count=1" &
	local readdd=$!

	# obliterate the worst service estimate
	sleep $((new_at_history / 3 + 1))
	dd if=/dev/zero of=$DIR/${tfile}2 bs=1M count=1

	estimate=$($LCTL get_param -n osc.$dev-osc-*.timeouts |
	    awk '/portal 6/ {print $5}')
	echo "service estimate dropped to $estimate"

	wait $writedd
	[[ $? == 0 ]] || error "write failed"
	wait $readdd
	[[ $? == 0 ]] || error "read failed"

	restore_lustre_params <$p
	if [ $brw_size -ne 4194304 ]
	then
		remount_client $MOUNT || error "remount_client failed"
	fi
	do_facet ost1 "echo $ldlm_enqueue_min_save > $ldlm_enqueue_min"
}
run_test 17b "timeout bulk get, dont evict client (3582)"

test_18a() {
	[ -z ${ost2_svc} ] && skip_env "needs 2 osts" && return 0

	do_facet_create_file client $TMP/$tfile 20K ||
		{ error_noexit "Create file $TMP/$tfile" ; return 0; }

	do_facet client mkdir -p $DIR/$tdir
	f=$DIR/$tdir/$tfile

	cancel_lru_locks osc
	pgcache_empty || return 1

	# 1 stripe on ost2
	$LFS setstripe -i 1 -c 1 $f
	stripe_index=$($LFS getstripe -i $f)
	if [ $stripe_index -ne 1 ]; then
		$LFS getstripe $f
		error "$f: stripe_index $stripe_index != 1" && return
	fi

	do_facet client cp $TMP/$tfile $f
	sync
	local osc2dev=`lctl get_param -n devices | grep ${ost2_svc}-osc- | egrep -v 'MDT' | awk '{print $1}'`
	$LCTL --device $osc2dev deactivate || return 3
	# my understanding is that there should be nothing in the page
	# cache after the client reconnects?
	rc=0
	pgcache_empty || rc=2
	$LCTL --device $osc2dev activate
	rm -f $f $TMP/$tfile
	return $rc
}
run_test 18a "manual ost invalidate clears page cache immediately"

test_18b() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	do_facet_create_file client $TMP/$tfile 20K ||
		{ error_noexit "Create file $TMP/$tfile" ; return 0; }

	do_facet client mkdir -p $DIR/$tdir
	f=$DIR/$tdir/$tfile

	cancel_lru_locks osc
	pgcache_empty || return 1

	$LFS setstripe -i 0 -c 1 $f
	stripe_index=$($LFS getstripe -i $f)
	if [ $stripe_index -ne 0 ]; then
		$LFS getstripe $f
		error "$f: stripe_index $stripe_index != 0" && return
	fi

	do_facet client cp $TMP/$tfile $f
	sync
	ost_evict_client
	# allow recovery to complete
	sleep $((TIMEOUT + 2))
	# my understanding is that there should be nothing in the page
	# cache after the client reconnects?
	rc=0
	pgcache_empty || rc=2
	rm -f $f $TMP/$tfile
	return $rc
}
run_test 18b "eviction and reconnect clears page cache (2766)"

test_18c() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	do_facet_create_file client $TMP/$tfile 20K ||
		{ error_noexit "Create file $TMP/$tfile" ; return 0; }

	do_facet client mkdir -p $DIR/$tdir
	f=$DIR/$tdir/$tfile

	cancel_lru_locks osc
	pgcache_empty || return 1

	$LFS setstripe -i 0 -c 1 $f
	stripe_index=$($LFS getstripe -i $f)
	if [ $stripe_index -ne 0 ]; then
		$LFS getstripe $f
		error "$f: stripe_index $stripe_index != 0" && return
	fi

	do_facet client cp $TMP/$tfile $f
	sync
	ost_evict_client

	# OBD_FAIL_OST_CONNECT_NET2
	# lost reply to connect request
	do_facet ost1 lctl set_param fail_loc=0x80000225
	# force reconnect
	sleep 1
	$LFS df $MOUNT > /dev/null 2>&1
	sleep 2
	# my understanding is that there should be nothing in the page
	# cache after the client reconnects?
	rc=0
	pgcache_empty || rc=2
	rm -f $f $TMP/$tfile
	return $rc
}
run_test 18c "Dropped connect reply after eviction handing (14755)"

test_19a() {
	local before=$(date +%s)
	local evict

	mount_client $DIR2 || error "failed to mount $DIR2"

	# cancel cached locks from OST to avoid eviction from it
	cancel_lru_locks osc

	do_facet client "stat $DIR > /dev/null"  ||
		error "failed to stat $DIR: $?"
	drop_ldlm_cancel "chmod 0777 $DIR2" ||
		error "failed to chmod $DIR2"

	umount_client $DIR2

	# let the client reconnect
	client_reconnect
	evict=$(do_facet client $LCTL get_param mdc.$FSNAME-MDT*.state |
		awk -F"[ [,]" '/EVICTED ]$/ \
			{ if (mx<$5) {mx=$5;} } END { print mx }')

	[[ -n "$evict" ]] && (( $evict >= $before )) ||
		(do_facet client $LCTL get_param mdc.$FSNAME-MDT*.state;
		    error "no eviction: $evict < before: $before")
}
run_test 19a "test expired_lock_main on mds (2867)"

test_19b() {
	local before=$(date +%s)
	local evict

	mount_client $DIR2 || error "failed to mount $DIR2: $?"

	# cancel cached locks from MDT to avoid eviction from it
	cancel_lru_locks mdc

	do_facet client $MULTIOP $DIR/$tfile Ow ||
		error "failed to run multiop: $?"
	drop_ldlm_cancel $MULTIOP $DIR2/$tfile Ow ||
		error "failed to ldlm_cancel: $?"

	umount_client $DIR2 || error "failed to unmount $DIR2: $?"
	do_facet client unlink $DIR/$tfile ||
		error "failed to unlink $DIR/$tfile: $?"

	# let the client reconnect
	client_reconnect
	evict=$(do_facet client $LCTL get_param osc.$FSNAME-OST*.state |
		awk -F"[ [,]" '/EVICTED ]$/ \
			{ if (mx < $5) {mx = $5;} } END { print mx }')

	[[ -n "$evict" ]] && (( $evict >= $before )) ||
		(do_facet client $LCTL get_param osc.$FSNAME-OST*.state;
		    error "no eviction: $evict < before: $before")
}
run_test 19b "test expired_lock_main on ost (2867)"

test_19c() {
	local BEFORE=`date +%s`

	mount_client $DIR2
	$LCTL set_param ldlm.namespaces.*.early_lock_cancel=0

	mkdir -p $DIR1/$tfile
	stat $DIR1/$tfile

#define OBD_FAIL_PTLRPC_CANCEL_RESEND 0x516
	do_facet mds $LCTL set_param fail_loc=0x80000516

	touch $DIR2/$tfile/file1 &
	PID1=$!
	# let touch to get blocked on the server
	sleep 2

	wait $PID1
	$LCTL set_param ldlm.namespaces.*.early_lock_cancel=1
	umount_client $DIR2

	# let the client reconnect
	sleep 5
	EVICT=$(do_facet client $LCTL get_param mdc.$FSNAME-MDT*.state |
	  awk -F"[ [,]" '/EVICTED ]$/ { if (mx<$5) {mx=$5;} } END { print mx }')

	[ -z "$EVICT" ] || [[ $EVICT -le $BEFORE ]] || error "eviction happened"
}
run_test 19c "check reconnect and lock resend do not trigger expired_lock_main"

test_20a() {	# bug 2983 - ldlm_handle_enqueue cleanup
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	mkdir -p $DIR/$tdir
	$LFS setstripe -i 0 -c 1 $DIR/$tdir/${tfile}
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
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	mkdir -p $DIR/$tdir
	$LFS setstripe -i 0 -c 1 $DIR/$tdir/${tfile}
	cancel_lru_locks osc
#define OBD_FAIL_LDLM_ENQUEUE_EXTENT_ERR 0x308
	do_facet ost1 lctl set_param fail_loc=0x80000308
	dd if=/etc/hosts of=$DIR/$tdir/$tfile && \
		error "didn't fail open enqueue" || true
}
run_test 20b "ldlm_handle_enqueue error (should return error)"

test_21a() {
	mkdir_on_mdt0 $DIR/$tdir-1
	mkdir_on_mdt0 $DIR/$tdir-2
	multiop_bg_pause $DIR/$tdir-1/f O_c || return 1
	close_pid=$!

	do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000129"
	$MULTIOP $DIR/$tdir-2/f Oc &
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
	mkdir_on_mdt0 $DIR/$tdir-1
	mkdir_on_mdt0 $DIR/$tdir-2
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
	mkdir_on_mdt0 $DIR/$tdir-1
	mkdir_on_mdt0 $DIR/$tdir-2
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
	mkdir_on_mdt0 $DIR/$tdir-1
	mkdir_on_mdt0 $DIR/$tdir-2
	multiop_bg_pause $DIR/$tdir-1/f O_c || return 1
	pid=$!

	do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000129"
	$MULTIOP $DIR/$tdir-2/f Oc &
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
	mkdir_on_mdt0 $DIR/$tdir-1
	mkdir_on_mdt0 $DIR/$tdir-2
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
	mkdir_on_mdt0 $DIR/$tdir-1
	mkdir_on_mdt0 $DIR/$tdir-2
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
	mkdir_on_mdt0 $DIR/$tdir-1
	mkdir_on_mdt0 $DIR/$tdir-2
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
	mkdir_on_mdt0 $DIR/$tdir-1
	mkdir_on_mdt0 $DIR/$tdir-2
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
	$MULTIOP $f2 Oc &
	close_pid=$!

	sleep 1
	$MULTIOP $f1 msu || return 1

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

test_24a() { # bug 11710 details correct fsync() behavior
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	mkdir -p $DIR/$tdir
	$LFS setstripe -i 0 -c 1 $DIR/$tdir
	cancel_lru_locks osc
	multiop_bg_pause $DIR/$tdir/$tfile Owy_wyc || return 1
	MULTI_PID=$!
	ost_evict_client
	kill -USR1 $MULTI_PID
	wait $MULTI_PID
	rc=$?
	lctl set_param fail_loc=0x0
	client_reconnect
	[ $rc -eq 0 ] &&
		error_ignore bz5494 "multiop didn't fail fsync: rc $rc" || true
}
run_test 24a "fsync error (should return error)"

test_24b() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	dmesg -c > /dev/null
	mkdir -p $DIR/$tdir
	lfs setstripe $DIR/$tdir -S 0 -i 0 -c 1 ||
		error "$LFS setstripe failed"
	cancel_lru_locks osc
	multiop_bg_pause $DIR/$tdir/$tfile-1 Ow8192_yc ||
		error "mulitop Ow8192_yc failed"

	MULTI_PID1=$!
	multiop_bg_pause $DIR/$tdir/$tfile-2 Ow8192_c ||
		error "mulitop Ow8192_c failed"

	MULTI_PID2=$!
	ost_evict_client

	kill -USR1 $MULTI_PID1
	wait $MULTI_PID1
	rc1=$?
	kill -USR1 $MULTI_PID2
	wait $MULTI_PID2
	rc2=$?
	lctl set_param fail_loc=0x0
	client_reconnect
	[ $rc1 -eq 0 -o $rc2 -eq 0 ] &&
	error_ignore bz5494 "multiop didn't fail fsync: $rc1 or close: $rc2" ||
		true

	dmesg | grep "dirty page discard:" ||
		error "no discarded dirty page found!"
}
run_test 24b "test dirty page discard due to client eviction"

test_26a() {      # was test_26 bug 5921 - evict dead exports by pinger
# this test can only run from a client on a separate node.
	remote_ost || { skip "local OST" && return 0; }
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0
	remote_mds || { skip "local MDS" && return 0; }

	if [ $(facet_host mgs) = $(facet_host ost1) ]; then
		skip "msg and ost1 are at the same node"
		return 0
	fi

	check_timeout || return 1

	# make sure all imports are connected and not IDLE
	do_facet client lfs df > /dev/null
	# make sure client will not be discarded by server due to LU-14708
	$LFS setstripe -c -1 -S 64K $MOUNT/$tfile
	dd if=/dev/zero of=$MOUNT/$tfile bs=64K count=$OSTCOUNT oflag=sync ||
		error "dd failed"
	sync; sleep 5; sync

# OBD_FAIL_PTLRPC_DROP_RPC 0x505
	do_facet client lctl set_param fail_loc=0x505
	local before=$(date +%s)
	local rc=0

	# evictor takes PING_EVICT_TIMEOUT to evict.
	# But if there's a race to start the evictor from various obds,
	# the loser might have to wait for the next ping.
	sleep $((TIMEOUT * 2))
	do_facet client lctl set_param fail_loc=0x0
	do_facet client lfs df > /dev/null

	local oscs=$(lctl dl | awk '/-osc-/ {print $4}')
	check_clients_evicted "$before ${oscs[@]}"
	check_clients_full 10 "${oscs[@]}"
}
run_test 26a "evict dead exports"

wait_client_evicted () {
	local facet=$1
	local exports=$2
	local timeout=$3
	local varsvc=${facet}_svc

	wait_update_cond $(facet_active_host $facet) \
		"lctl get_param -n *.${!varsvc}.num_exports | cut -d' ' -f2" \
		"-le" $((exports - 1)) $timeout
}

test_26b() {      # bug 10140 - evict dead exports by pinger
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	[[ $(facet_host mgs) != $(facet_host ost1) ]] ||
		skip "msg and ost1 are at the same node"

	check_timeout || return 1
	clients_up
	zconf_mount $HOSTNAME $MOUNT2 ||
                { error "Failed to mount $MOUNT2"; return 2; }
	# make sure all imports are connected and not IDLE
	do_facet client $LFS df > /dev/null
	$LFS setstripe -c -1 $MOUNT/$tfile

	local mds_nexp=$(do_facet mds1 \
		lctl get_param -n mdt.${mds1_svc}.num_exports)
	local ost_nexp=$(do_facet ost1 \
		lctl get_param -n obdfilter.${ost1_svc}.num_exports)
	# must be equal on all the nodes
	local INTERVAL=$(do_facet $SINGLEMDS lctl get_param -n ping_interval)
	local AT_MAX_SAVED=$(at_max_get mds1)

	at_max_set $TIMEOUT mds1
	at_max_set $TIMEOUT ost1
	stack_trap "at_max_set $AT_MAX_SAVED mds1" EXIT
	stack_trap "at_max_set $AT_MAX_SAVED ost1" EXIT

	echo "starting with '$ost_nexp' OST and '$mds_nexp' MDS exports"

	zconf_umount $HOSTNAME $MOUNT2 -f

	# see ptlrpc_export_timeout() for the pinger case; take a bit more the test sake
	local TOUT=$((INTERVAL * 2 + (TIMEOUT / 20 + 5 + TIMEOUT) * 3))
	TOUT=$((TOUT + (TOUT >> 3)))
	echo i $INTERVAL m $AT_MAX_SAVED t $TIMEOUT $TOUT
	wait_client_evicted ost1 $ost_nexp $TOUT ||
		error "Client was not evicted by OSS"
	wait_client_evicted mds1 $mds_nexp $TOUT ||
		error "Client was not evicted by MDS"
}
run_test 26b "evict dead exports"

test_27() {
	mkdir_on_mdt0 $DIR/$tdir
	writemany -q -a $DIR/$tdir/$tfile 0 5 &
	CLIENT_PID=$!
	sleep 1
	local save_FAILURE_MODE=$FAILURE_MODE
	FAILURE_MODE="SOFT"
	facet_failover $SINGLEMDS
#define OBD_FAIL_OSC_SHUTDOWN            0x407
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000407
	# need to wait for reconnect
	echo waiting for fail_loc
	wait_update_facet $SINGLEMDS "lctl get_param -n fail_loc" "-2147482617"
	facet_failover $SINGLEMDS
	#no crashes allowed!
        kill -USR1 $CLIENT_PID
	wait $CLIENT_PID
	true
	FAILURE_MODE=$save_FAILURE_MODE
}
run_test 27 "fail LOV while using OSC's"

test_28() {      # bug 6086 - error adding new clients
	do_facet client mcreate $DIR/$tfile       || return 1
	drop_bl_callback_once "chmod 0777 $DIR/$tfile" ||
		echo "evicted as expected"
	#define OBD_FAIL_MDS_CLIENT_ADD 0x12f
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x8000012f"
	# fail once (evicted), reconnect fail (fail_loc), ok
	client_up || (sleep 10; client_up) || (sleep 10; client_up) || error "reconnect failed"
	rm -f $DIR/$tfile
	fail $SINGLEMDS		# verify MDS last_rcvd can be loaded
}
run_test 28 "handle error adding new clients (bug 6086)"

test_29a() { # bug 22273 - error adding new clients
	#define OBD_FAIL_TGT_CLIENT_ADD 0x711
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000711"
	# fail abort so client will be new again
	fail_abort $SINGLEMDS
	client_up || error "reconnect failed"
	wait_osc_import_state $SINGLEMDS ost FULL
	return 0
}
run_test 29a "error adding new clients doesn't cause LBUG (bug 22273)"

test_29b() { # bug 22273 - error adding new clients
	#define OBD_FAIL_TGT_CLIENT_ADD 0x711
	do_facet ost1 "lctl set_param fail_loc=0x80000711"
	# fail abort so client will be new again
	fail_abort ost1
	client_up || error "reconnect failed"
	return 0
}
run_test 29b "error adding new clients doesn't cause LBUG (bug 22273)"

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
	[ $rc -eq 0 ] ||
		error_ignore bz13652 "writemany returned rc $rc" || true
}
run_test 50 "failover MDS under load"

test_51() {
	#define OBD_FAIL_MDS_SYNC_CAPA_SL                    0x1310
	do_facet ost1 lctl set_param fail_loc=0x00001310

	mkdir_on_mdt0 $DIR/$tdir
	# put a load of file creates/writes/deletes
	writemany -q $DIR/$tdir/$tfile 0 5 &
	CLIENT_PID=$!
	sleep 1
	FAILURE_MODE="SOFT"
	facet_failover $SINGLEMDS
	# failover at various points during recovery
	SEQ="1 5 10 $(seq $TIMEOUT 5 $(($TIMEOUT+10)))"
	echo will failover at $SEQ
	for i in $SEQ; do
		#echo failover in $i sec
		log "$TESTNAME: failover in $i sec"
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
	[ $rc -eq 0 ] ||
		error_ignore bz13652 "writemany returned rc $rc" || true
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
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

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
test_53a() {
	touch $DIR/$tfile
	drop_mdt_ldlm_reply "openfile -f O_RDWR:O_CREAT -m 0755 $DIR/$tfile" ||\
		return 2
}
run_test 53a "touch: drop rep"

test_53b() {
	touch $DIR/$tfile
	sync
	drop_mdt_ldlm_reply "openfile -f O_RDWR:O_CREAT -m 0755 $DIR/$tfile" ||
		return 2
}
run_test 53b "touch: drop rep"

test_53c() {
	rm -rf $DIR/$tfile
	sync
	drop_mdt_ldlm_reply "openfile -f O_RDWR:O_CREAT -m 0755 $DIR/$tfile" ||
		return 2
}
run_test 53c "touch: drop rep"

test_54() {
	zconf_mount $(hostname) $MOUNT2
	touch $DIR/$tfile
	touch $DIR2/$tfile.1
	sleep 10
	cat $DIR2/$tfile.missing # save transno = 0, rc != 0 into last_rcvd
	fail $SINGLEMDS
	umount $MOUNT2
	ERROR=$(dmesg | egrep "(test 54|went back in time)" | tail -n1 |
		grep "went back in time")
	[ x"$ERROR" == x ] || error "back in time occured"
}
run_test 54 "back in time"

# bug 11330 - liblustre application death during I/O locks up OST
test_55() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	mkdir -p $DIR/$tdir

	# This test assumes relatively small max_dirty_mb setting
	# which we want to walk away from, so just for it we will
	# temporarily lower the value
	local max_dirty_mb=$(lctl get_param -n osc.*.max_dirty_mb | head -n 1)
	lctl set_param -n osc.*.max_dirty_mb=32
	stack_trap "lctl set_param osc.*.max_dirty_mb=$max_dirty_mb" EXIT

	# Minimum pass speed is 2MBps
	local ddtimeout=64
	# LU-2887/LU-3089 - set min pass speed to 500KBps
	[ "$ost1_FSTYPE" = zfs ] && ddtimeout=256

	# first dd should be finished quickly
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/$tfile-1
	dd if=/dev/zero of=$DIR/$tdir/$tfile-1 bs=32M count=4 &
	DDPID=$!
	count=0
	echo  "step1: testing ......"
	while kill -0 $DDPID 2> /dev/null; do
		let count++
		if [ $count -gt $ddtimeout ]; then
			error "dd should be finished!"
		fi
		sleep 1
	done
	echo "(dd_pid=$DDPID, time=$count)successful"

	$LFS setstripe -c 1 -i 0 $DIR/$tdir/$tfile-2
	#define OBD_FAIL_OST_DROP_REQ            0x21d
	do_facet ost1 lctl set_param fail_loc=0x0000021d
	# second dd will be never finished
	dd if=/dev/zero of=$DIR/$tdir/$tfile-2 bs=32M count=4 &
	DDPID=$!
	count=0
	echo  "step2: testing ......"
	while [ $count -le $ddtimeout ]; do
		if ! kill -0 $DDPID 2> /dev/null; then
			ls -l $DIR/$tdir
			error "dd shouldn't be finished! (time=$count)"
		fi
		let count++
		sleep 1
	done
	echo "(dd_pid=$DDPID, time=$count)successful"

	#Recover fail_loc and dd will finish soon
	do_facet ost1 lctl set_param fail_loc=0
	count=0
	echo  "step3: testing ......"
	while kill -0 $DDPID 2> /dev/null; do
		let count++
		if [ $count -gt $((ddtimeout + 440)) ]; then
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
	stat $DIR/$tfile || error "stat failed"
	do_facet $SINGLEMDS "lctl set_param fail_loc=0"
	rm -f $DIR/$tfile
}
run_test 56 "do not fail on getattr resend"

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
	touch $DIR/$tfile
	ls -la $DIR/$tfile
	lctl set_param fail_loc=0x80000801
	cp $DIR/$tfile /dev/null &
	pid=$!
	sleep 1
	lctl set_param fail_loc=0
	drop_bl_callback_once rm -f $DIR/$tfile
	wait $pid
	# the first 'df' could tigger the eviction caused by
	# 'drop_bl_callback_once', and it's normal case.
	# but the next 'df' should return successfully.
	do_facet client "df $DIR" || do_facet client "df $DIR"
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

test_60() {
	local num_files=${COUNT:-5000}
	test_mkdir $DIR/$tdir

	# Register (and start) changelog
	changelog_register || error "changelog_register failed"

	# Generate a large number of changelog entries
	createmany -o $DIR/$tdir/$tfile $num_files
	sync
	sleep 5

	# Unlink files in the background
	unlinkmany $DIR/$tdir/$tfile $num_files &
	local client_pid=$!
	sleep 1

	# Failover the MDS while unlinks are happening
	facet_failover $SINGLEMDS

	# Wait for unlinkmany to finish
	wait $client_pid

	# Check if all the create/unlink events were recorded
	# in the changelog
	local cl_count=$(changelog_dump | grep -c UNLNK)
	echo "$cl_count unlinks in changelog"

	changelog_deregister || error "changelog_deregister failed"
	if ! changelog_users $SINGLEMDS | grep -q "^cl"; then
		[ $cl_count -eq $num_files ] ||
			error "Recorded $cl_count of $num_files unlinks"
		# Also make sure we can clear large changelogs
		cl_count=$(changelog_dump | wc -l)
		[ $cl_count -le 2 ] ||
			error "Changelog not empty: $cl_count entries"
	else # If other users, there may be other unlinks in the log
		[ $cl_count -ge $num_files ] ||
			error "Recorded $cl_count of $num_files unlinks"
		changelog_users $SINGLEMDS
		echo "other changelog users; can't verify clear"
	fi
}
run_test 60 "Add Changelog entries during MDS failover"

test_61()
{
	local mdtosc=$(get_mdtosc_proc_path $SINGLEMDS $FSNAME-OST0000)
	mdtosc=${mdtosc/-MDT*/-MDT\*}
	local cflags="osc.$mdtosc.connect_flags"
	do_facet $SINGLEMDS "lctl get_param -n $cflags" |grep -q skip_orphan
	[ $? -ne 0 ] && skip "don't have skip orphan feature" && return

	mkdir_on_mdt0 $DIR/$tdir || error "mkdir dir $DIR/$tdir failed"
	# Set the default stripe of $DIR/$tdir to put the files to ost1
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	replay_barrier $SINGLEMDS
	createmany -o $DIR/$tdir/$tfile-%d 10
	local oid=$(do_facet ost1 "lctl get_param -n \
		obdfilter.${ost1_svc}.last_id" | sed -e 's/.*://')

	fail_abort $SINGLEMDS

	touch $DIR/$tdir/$tfile
	local id=$($LFS getstripe $DIR/$tdir/$tfile |
		awk '$1 == 0 { print $2 }')
	[ $id -le $oid ] && error "the orphan objid was reused, failed"

	# Cleanup
	rm -rf $DIR/$tdir
}
run_test 61 "Verify to not reuse orphan objects - bug 17025"

# test_62 as seen it b2_1 please do not reuse test_62
#test_62()
#{
#	zconf_umount `hostname` $DIR
#	#define OBD_FAIL_PTLRPC_DELAY_IMP_FULL   0x516
#	lctl set_param fail_loc=0x516
#	mount_client $DIR
#}
#run_test 62 "Verify connection flags race - bug LU-1716"

test_65() {
	mount_client $DIR2

	#grant lock1, export2
	$LFS setstripe -i -0 $DIR2/$tfile || error "setstripe failed"
	$MULTIOP $DIR2/$tfile Ow  || error "multiop failed"

#define OBD_FAIL_LDLM_BL_EVICT            0x31e
	do_facet ost $LCTL set_param fail_loc=0x31e
	#get waiting lock2, export1
	$MULTIOP $DIR/$tfile Ow &
	PID1=$!
	# let enqueue to get asleep
	sleep 2

	#get lock2 blocked
	$MULTIOP $DIR2/$tfile Ow &
	PID2=$!
	sleep 2

	#evict export1
	ost_evict_client

	sleep 2
	do_facet ost $LCTL set_param fail_loc=0

	wait $PID1
	wait $PID2

	umount_client $DIR2
}
run_test 65 "lock enqueue for destroyed export"

test_66()
{
	[[ "$MDS1_VERSION" -ge $(version_code 2.7.51) ]] ||
		skip "Need MDS version at least 2.7.51"

	# modify dir so that next revalidate would not obtain UPDATE lock
	touch $DIR

	# drop 1 reply with UPDATE lock
	mcreate $DIR/$tfile || error "mcreate failed: $?"
	drop_mdt_ldlm_reply_once "stat $DIR/$tfile" &
	sleep 2

	# make the re-sent lock to sleep
#define OBD_FAIL_MDS_RESEND              0x136
	do_nodes $(osts_nodes) $LCTL set_param fail_loc=0x80000136

	#initiate the re-connect & re-send
	local mdtname="MDT0000"
	local mdccli=$($LCTL dl | grep "${mdtname}-mdc" | awk '{print $4;}')
	local conn_uuid=$($LCTL get_param -n mdc.${mdccli}.conn_uuid)
	$LCTL set_param "mdc.${mdccli}.import=connection=${conn_uuid}"
	sleep 2

	#initiate the client eviction while enqueue re-send is in progress
	mds_evict_client

	client_reconnect
	wait
}
run_test 66 "lock enqueue re-send vs client eviction"

test_67()
{
#define OBD_FAIL_PTLRPC_CONNECT_RACE	 0x531
	$LCTL set_param fail_loc=0x80000531

	local mdtname="MDT0000"
	local mdccli=$($LCTL dl | grep "${mdtname}-mdc" | awk '{print $4;}')
	local conn_uuid=$($LCTL get_param -n mdc.${mdccli}.mds_conn_uuid)
	$LCTL set_param "mdc.${mdccli}.import=connection=${conn_uuid}" &
	sleep 2

	mds_evict_client
	sleep 1

	client_reconnect
	wait
}
run_test 67 "connect vs import invalidate race"

check_cli_ir_state()
{
	local NODE=${1:-$HOSTNAME}
	local st
	st=$(do_node $NODE "lctl get_param mgc.*.ir_state |
                            awk '/imperative_recovery:/ { print \\\$2}'")
	[ $st != ON -o $st != OFF -o $st != ENABLED -o $st != DISABLED ] ||
		error "Error state $st, must be ENABLED or DISABLED"
	echo -n $st
}

check_target_ir_state()
{
	local target=${1}
	local name=${target}_svc
	local recovery_proc=obdfilter.${!name}.recovery_status
	local st

	while : ; do
		st=$(do_facet $target "$LCTL get_param -n $recovery_proc |
			awk '/status:/{ print \\\$2}'")
		[ x$st = xRECOVERING ] || break
	done
	st=$(do_facet $target "lctl get_param -n $recovery_proc |
		awk '/IR:/{ print \\\$2}'")
	[ $st != ON -o $st != OFF -o $st != ENABLED -o $st != DISABLED ] ||
		error "Error state $st, must be ENABLED or DISABLED"
	echo -n $st
}

set_ir_status()
{
	do_facet mgs lctl set_param -n mgs.MGS.live.$FSNAME="state=$1"
}

get_ir_status()
{
	local state=$(do_facet mgs "lctl get_param -n mgs.MGS.live.$FSNAME |
		awk '/state:/{ print \\\$2 }'")
	echo -n ${state/,/}
}

nidtbl_version_mgs()
{
	local ver=$(do_facet mgs "lctl get_param -n mgs.MGS.live.$FSNAME |
		awk '/nidtbl_version:/{ print \\\$2 }'")
	echo -n $ver
}

# nidtbl_version_client <mds1|client> [node]
nidtbl_version_client()
{
	local cli=$1
	local node=${2:-$HOSTNAME}

	if [ X$cli = Xclient ]; then
		cli=$FSNAME-client
	else
		local obdtype=${cli/%[0-9]*/}
		[ $obdtype != mds ] && error "wrong parameters $cli"

		node=$(facet_active_host $cli)
		local t=${cli}_svc
		cli=${!t}
	fi

	local vers=$(do_node $node "lctl get_param -n mgc.*.ir_state" |
		awk "/$cli/{print \$6}" |sort -u)

	# in case there are multiple mounts on the client node
	local arr=($vers)
	[ ${#arr[@]} -ne 1 ] && error "versions on client node mismatch"
	echo -n $vers
}

nidtbl_versions_match()
{
	[ $(nidtbl_version_mgs) -eq $(nidtbl_version_client ${1:-client}) ]
}

target_instance_match()
{
	local srv=$1
	local obdtype
	local cliname

	obdtype=${srv/%[0-9]*/}
	case $obdtype in
	mds)
		obdname="mdt"
		cliname="mdc"
		;;
	ost)
		obdname="obdfilter"
		cliname="osc"
		;;
	*)
		error "invalid target type" $srv
		return 1
		;;
	esac

	local target=${srv}_svc
	local si=$(do_facet $srv lctl get_param -n $obdname.${!target}.instance)
	local ci=$(lctl get_param -n $cliname.${!target}-${cliname}-*.import |
		awk '/instance/{ print $2 }' | head -n1)

	return $([ $si -eq $ci ])
}

test_100()
{
	do_facet mgs $LCTL list_param mgs.*.ir_timeout ||
		{ skip "MGS without IR support"; return 0; }

	# MDT was just restarted in the previous test, make sure everything
	# is all set.
	local cnt=30
	while [ $cnt -gt 0 ]; do
		nidtbl_versions_match && break
		sleep 1
		cnt=$((cnt - 1))
	done

	# disable IR
	set_ir_status disabled

	local prev_ver=$(nidtbl_version_client client)

	local saved_FAILURE_MODE=$FAILURE_MODE
	[ $(facet_host mgs) = $(facet_host ost1) ] && FAILURE_MODE="SOFT"
	fail ost1

	# valid check
	[ $(nidtbl_version_client client) -eq $prev_ver ] ||
		error "version must not change due to IR disabled"
	target_instance_match ost1 || error "instance mismatch"

	# restore env
	set_ir_status full
	FAILURE_MODE=$saved_FAILURE_MODE
}
run_test 100 "IR: Make sure normal recovery still works w/o IR"

test_101a()
{
	do_facet mgs $LCTL list_param mgs.*.ir_timeout ||
		skip "MGS without IR support"

	set_ir_status full

	local ost1_imp=$(get_osc_import_name client ost1)

	# disable pinger recovery
	lctl set_param -n osc.$ost1_imp.pinger_recov=0
	stack_trap "$LCTL set_param -n osc.$ost1_imp.pinger_recov=1" EXIT

	fail ost1

	target_instance_match ost1 || error "instance mismatch"
	nidtbl_versions_match || error "version must match"
}
run_test 101a "IR: Make sure IR works w/o normal recovery"

test_101b()
{
	do_facet mgs $LCTL list_param mgs.*.ir_timeout ||
		skip "MGS without IR support"

	set_ir_status full

	local ost1_imp=$(get_osc_import_name client ost1)

#define OBD_FAIL_OST_PREPARE_DELAY	 0x247
	do_facet ost1 "$LCTL set_param fail_loc=0x247"
	# disable pinger recovery
	$LCTL set_param -n osc.$ost1_imp.pinger_recov=0
	stack_trap "$LCTL set_param -n osc.$ost1_imp.pinger_recov=1" EXIT

#OST may return EAGAIN if it is not configured yet
	fail ost1
}
run_test 101b "IR: Make sure IR works w/o normal recovery and proceed EAGAIN"

test_102()
{
	do_facet mgs $LCTL list_param mgs.*.ir_timeout ||
		{ skip "MGS without IR support"; return 0; }

	local clients=${CLIENTS:-$HOSTNAME}
	local old_version
	local new_version
	local mgsdev=mgs

	set_ir_status full

	# let's have a new nidtbl version
	fail ost1

	# sleep for a while so that clients can see the failure of ost
	# it must be MGC_TIMEOUT_MIN_SECONDS + MGC_TIMEOUT_RAND_CENTISEC.
	# int mgc_request.c:
	# define MGC_TIMEOUT_MIN_SECONDS   5
	# define MGC_TIMEOUT_RAND_CENTISEC 0x1ff /* ~500 *
	local count=30  # 20 seconds at most
	while [ $count -gt 0 ]; do
		nidtbl_versions_match && break
		sleep 1
		count=$((count-1))
	done

	nidtbl_versions_match || error "nidtbl mismatch"

	# get the version #
	old_version=$(nidtbl_version_client client)

	zconf_umount_clients $clients $MOUNT || error "Cannot umount client"

	# restart mgs
	combined_mgs_mds && mgsdev=mds1
	remount_facet $mgsdev
	fail ost1

	zconf_mount_clients $clients $MOUNT || error "Cannot mount client"

	# check new version
	new_version=$(nidtbl_version_client client)
	[ $new_version -lt $old_version ] &&
		error "nidtbl version wrong after mgs restarts"
	return 0
}
run_test 102 "IR: New client gets updated nidtbl after MGS restart"

test_103()
{
	do_facet mgs $LCTL list_param mgs.*.ir_timeout ||
		{ skip "MGS without IR support"; return 0; }

	combined_mgs_mds && skip "needs separate mgs and mds" && return 0

	# workaround solution to generate config log on the mds
	remount_facet mds1

	stop mgs
	stop mds1

	# We need this test because mds is like a client in IR context.
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS ||
		error "MDS should start w/o mgs"

	# start mgs and remount mds w/ ir
	start mgs $(mgsdevname) $MGS_MOUNT_OPTS
	clients_up

	# remount client so that fsdb will be created on the MGS
	umount_client $MOUNT || error "umount failed"
	mount_client $MOUNT || error "mount failed"

	# sleep 30 seconds so the MDS has a chance to detect MGS restarting
	local count=30
	while [ $count -gt 0 ]; do
		[ $(nidtbl_version_client mds1) -ne 0 ] && break
		sleep 1
		count=$((count-1))
	done

	# after a while, mds should be able to reconnect to mgs and fetch
	# up-to-date nidtbl version
	nidtbl_versions_match mds1 || error "mds nidtbl mismatch"

	# reset everything
	set_ir_status full
}
run_test 103 "IR: MDS can start w/o MGS and get updated nidtbl later"

test_104()
{
	do_facet mgs $LCTL list_param mgs.*.ir_timeout ||
		{ skip "MGS without IR support"; return 0; }

	set_ir_status full

	stop ost1
	start ost1 $(ostdevname 1) "$OST_MOUNT_OPTS -onoir" ||
		error "OST1 cannot start"
	clients_up

	local ir_state=$(check_target_ir_state ost1)

	[ $ir_state = "DISABLED" -o $ir_state = "OFF" ] ||
		error "ir status on ost1 should be DISABLED"
}
run_test 104 "IR: ost can disable IR voluntarily"

test_105()
{
	[ -z "$RCLIENTS" ] && skip "Needs multiple clients" && return 0
	do_facet mgs $LCTL list_param mgs.*.ir_timeout ||
		{ skip "MGS without IR support"; return 0; }

	set_ir_status full

	# get one of the clients from client list
	local rcli=$(echo $RCLIENTS |cut -d' ' -f 1)

	local mount_opts=${MOUNT_OPTS:+$MOUNT_OPTS,}noir
	zconf_umount $rcli $MOUNT || error "umount failed"
	zconf_mount $rcli $MOUNT $mount_opts || error "mount failed"

	# make sure lustre mount at $rcli disabling IR
	local ir_state=$(check_cli_ir_state $rcli)
	[ $ir_state = "DISABLED" -o $ir_state = "OFF" ] ||
		error "IR state must be DISABLED at $rcli"

	# Since the client just mounted, its last_rcvd entry is not on disk.
	# Send an RPC so exp_need_sync forces last_rcvd to commit this export
	# so the client can reconnect during OST recovery (LU-924, LU-1582)
	$LFS setstripe -i 0 $DIR/$tfile
	dd if=/dev/zero of=$DIR/$tfile bs=1M count=1 conv=sync

	# make sure MGS's state is Partial
	[ $(get_ir_status) = "partial" ] || error "MGS IR state must be partial"

	fail ost1
	# make sure IR on ost1 is DISABLED
	local ir_state=$(check_target_ir_state ost1)
	[ $ir_state = "DISABLED" -o $ir_state = "OFF" ] ||
		error "IR status on ost1 should be DISABLED"

	# remount with the default MOUNT_OPTS
	zconf_umount $rcli $MOUNT || error "umount failed"
	zconf_mount $rcli $MOUNT || error "mount failed"

	# make sure MGS's state is full
	[ $(get_ir_status) = "full" ] || error "MGS IR status must be full"

	fail ost1
	# make sure IR on ost1 is ENABLED
	local ir_state=$(check_target_ir_state ost1)
	[ $ir_state = "ENABLED" -o $ir_state = "ON" ] ||
		error "IR status on ost1 should be ENABLED"

	return 0
}
run_test 105 "IR: NON IR clients support"

cleanup_106() {
	trap 0
	umount_client $DIR2
	debugrestore
}

test_106() { # LU-1789
	[[ "$MDS1_VERSION" -ge $(version_code 2.3.50) ]] ||
		skip "Need MDS version at least 2.3.50"

#define OBD_FAIL_MDC_LIGHTWEIGHT         0x805
	$LCTL set_param fail_loc=0x805

	debugsave
	trap cleanup_106 EXIT

	# enable lightweight flag on mdc connection
	mount_client $DIR2

	local MDS_NEXP=$(do_facet $SINGLEMDS \
			 lctl get_param -n mdt.${mds1_svc}.num_exports |
			 cut -d' ' -f2)
	$LCTL set_param fail_loc=0

	touch $DIR2/$tfile || error "failed to create empty file"
	replay_barrier $SINGLEMDS

	$LCTL set_param debug=ha
	$LCTL clear
	facet_failover $SINGLEMDS

	# lightweight goes through LUSTRE_IMP_RECOVER during failover
	touch -c $DIR2/$tfile || true
	$LCTL dk $TMP/lustre-log-$TESTNAME.log
	recovered=$(awk '/MDT0000-mdc-[0-9a-f]*. lwp recover/ { print }' \
		    $TMP/lustre-log-$TESTNAME.log)
	[ -z "$recovered" ] && error "lightweight client was not recovered"

	# and all operations performed by lightweight client should be
	# synchronous, so the file created before mds restart should be there
	$CHECKSTAT -t file $DIR/$tfile || error "file not present"
	rm -f $DIR/$tfile

	cleanup_106
}
run_test 106 "lightweight connection support"

test_107 () {
	local CLIENT_PID
	local close_pid

	mkdir_on_mdt0 $DIR/$tdir
	# OBD_FAIL_MDS_REINT_NET_REP   0x119
	do_facet $SINGLEMDS lctl set_param fail_loc=0x119
	multiop $DIR/$tdir D_c &
	close_pid=$!
	mkdir $DIR/$tdir/dir_106 &
	CLIENT_PID=$!
	do_facet $SINGLEMDS lctl set_param fail_loc=0
	fail $SINGLEMDS

	wait $CLIENT_PID || rc=$?
	checkstat -t dir $DIR/$tdir/dir_106 || return 1

	kill -USR1 $close_pid
	wait $close_pid || return 2

	return $rc
}
run_test 107 "drop reint reply, then restart MDT"

test_108() {
	mkdir -p $DIR/$tdir
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	dd if=/dev/zero of=$DIR/$tdir/$tfile bs=1M count=256 &
	local dd_pid=$!
	sleep 0.1

	ost_evict_client

	wait $dd_pid

	client_up || error "reconnect failed"
	rm -f $DIR/$tdir/$tfile
}
run_test 108 "client eviction don't crash"

test_110a () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	local remote_dir=$DIR/$tdir/remote_dir
	local mdtidx=1
	local num

	#prepare for 110 test, which need set striped dir on remote MDT.
	for num in $(seq $MDSCOUNT); do
		do_facet mds$num \
			lctl set_param -n mdt.$FSNAME*.enable_remote_dir=1 \
				2>/dev/null
	done

	mkdir_on_mdt0 $DIR/$tdir
	drop_request "$LFS mkdir -i $mdtidx -c2 $remote_dir" ||
		error "lfs mkdir failed"
	local diridx=$($LFS getstripe -m $remote_dir)
	[ $diridx -eq $mdtidx ] || error "$diridx != $mdtidx"

	rm -rf $DIR/$tdir || error "rmdir failed"
}
run_test 110a "create remote directory: drop client req"

test_110b () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	local remote_dir=$DIR/$tdir/remote_dir
	local mdtidx=1

	mkdir_on_mdt0 $DIR/$tdir
	drop_reint_reply "$LFS mkdir -i $mdtidx -c2 $remote_dir" ||
		error "lfs mkdir failed"

	diridx=$($LFS getstripe -m $remote_dir)
	[ $diridx -eq $mdtidx ] || error "$diridx != $mdtidx"

	rm -rf $DIR/$tdir || error "rmdir failed"
}
run_test 110b "create remote directory: drop Master rep"

test_110c () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	local remote_dir=$DIR/$tdir/remote_dir
	local mdtidx=1

	mkdir_on_mdt0 $DIR/$tdir
	drop_update_reply $mdtidx "$LFS mkdir -i $mdtidx -c2 $remote_dir" ||
		error "lfs mkdir failed"

	diridx=$($LFS getstripe -m $remote_dir)
	[ $diridx -eq $mdtidx ] || error "$diridx != $mdtidx"

	rm -rf $DIR/$tdir || error "rmdir failed"
}
run_test 110c "create remote directory: drop update rep on slave MDT"

test_110d () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	local remote_dir=$DIR/$tdir/remote_dir
	local MDTIDX=1

	mkdir_on_mdt0 $DIR/$tdir
	$LFS mkdir -i $MDTIDX -c2 $remote_dir || error "lfs mkdir failed"

	drop_request "rm -rf $remote_dir" || error "rm remote dir failed"

	rm -rf $DIR/$tdir || error "rmdir failed"

	return 0
}
run_test 110d "remove remote directory: drop client req"

test_110e () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	local remote_dir=$DIR/$tdir/remote_dir
	local MDTIDX=1

	mkdir_on_mdt0 $DIR/$tdir
	$LFS mkdir -i $MDTIDX -c2 $remote_dir  || error "lfs mkdir failed"
	drop_reint_reply "rm -rf $remote_dir" || error "rm remote dir failed"

	rm -rf $DIR/$tdir || error "rmdir failed"

	return 0
}
run_test 110e "remove remote directory: drop master rep"

test_110f () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	local remote_dir=$DIR/$tdir/remote_dir
	local MDTIDX=1

	mkdir_on_mdt0 $DIR/$tdir
	$LFS mkdir -i $MDTIDX -c2 $remote_dir || error "lfs mkdir failed"
	drop_update_reply $MDTIDX "rm -rf $remote_dir" ||
					error "rm remote dir failed"

	rm -rf $DIR/$tdir || error "rmdir failed"
}
run_test 110f "remove remote directory: drop slave rep"

test_110g () {
	[[ "$MDS1_VERSION" -ge $(version_code 2.11.0) ]] ||
		skip "Need MDS version at least 2.11.0"

	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"

	mkdir_on_mdt0 $DIR/$tdir
	touch $DIR/$tdir/$tfile

	# OBD_FAIL_MDS_REINT_NET_REP	0x119
	do_facet mds1 $LCTL set_param fail_loc=0x119
	$LFS migrate -m 1 $DIR/$tdir &
	migrate_pid=$!
	sleep 5
	do_facet mds1 $LCTL set_param fail_loc=0
	wait $migrate_pid

	local mdt_index
	mdt_index=$($LFS getstripe -m $DIR/$tdir)
	[ $mdt_index == 1 ] || error "$tdir is not on MDT1"
	mdt_index=$($LFS getstripe -m $DIR/$tdir/$tfile)
	[ $mdt_index == 1 ] || error "$tfile is not on MDT1"

	rm -rf $DIR/$tdir || error "rmdir failed"
}
run_test 110g "drop reply during migration"

test_110h () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	[[ "$MDS1_VERSION" -ge $(version_code 2.7.56) ]] ||
		skip "Need MDS version at least 2.7.56"

	local src_dir=$DIR/$tdir/source_dir
	local tgt_dir=$DIR/$tdir/target_dir
	local MDTIDX=1

	mkdir -p $src_dir
	$LFS mkdir -i $MDTIDX $tgt_dir

	dd if=/etc/hosts of=$src_dir/src_file
	touch $tgt_dir/tgt_file
	drop_update_reply $MDTIDX \
		"mrename $src_dir/src_file $tgt_dir/tgt_file" ||
		error "mrename failed"

	$CHECKSTAT -t file $src_dir/src_file &&
				error "src_file present after rename"

	diff /etc/hosts $tgt_dir/tgt_file ||
			error "file changed after rename"

}
run_test 110h "drop update reply during cross-MDT file rename"

test_110i () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	[[ "$MDS1_VERSION" -ge $(version_code 2.7.56) ]] ||
		skip "Need MDS version at least 2.7.56"

	local src_dir=$DIR/$tdir/source_dir
	local tgt_dir=$DIR/$tdir/target_dir
	local MDTIDX=1

	mkdir -p $src_dir
	$LFS mkdir -i $MDTIDX $tgt_dir

	mkdir $src_dir/src_dir
	touch $src_dir/src_dir/a
	mkdir $tgt_dir/tgt_dir
	drop_update_reply $MDTIDX \
		"mrename $src_dir/src_dir $tgt_dir/tgt_dir" ||
		error "mrename failed"

	$CHECKSTAT -t dir $src_dir/src_dir &&
			error "src_dir present after rename"

	$CHECKSTAT -t dir $tgt_dir/tgt_dir ||
				error "tgt_dir not present after rename"

	$CHECKSTAT -t file $tgt_dir/tgt_dir/a ||
				error "a not present after rename"
}
run_test 110i "drop update reply during cross-MDT dir rename"

test_110j () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	[[ "$MDS1_VERSION" -ge $(version_code 2.7.56) ]] ||
		skip "Need MDS version at least 2.7.56"

	local remote_dir=$DIR/$tdir/remote_dir
	local local_dir=$DIR/$tdir/local_dir
	local MDTIDX=1

	mkdir_on_mdt0 $DIR/$tdir
	mkdir $DIR/$tdir/local_dir
	$LFS mkdir -i $MDTIDX $remote_dir

	touch $local_dir/local_file
	drop_update_reply $MDTIDX \
		"ln $local_dir/local_file $remote_dir/remote_file" ||
		error "ln failed"

	$CHECKSTAT -t file $remote_dir/remote_file ||
				error "remote not present after ln"
}
run_test 110j "drop update reply during cross-MDT ln"

test_110k() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTS"
	[[ "$MDS1_VERSION" -ge $(version_code 2.12.55) ]] ||
		skip "Need MDS version at least 2.12.55"

	umount $MOUNT
	stop mds2 || error "stop mds2 failed"

#define OBD_FAIL_FLD_QUERY_REQ 0x1103
	do_facet mds2 lctl set_param fail_loc=0x80001103
	local OPTS="$MDS_MOUNT_OPTS -o abort_recovery"
	start mds2 $(mdsdevname 2) $OPTS ||
		error "start MDS with abort_recovery should succeed"
	do_facet mds2 lctl set_param fail_loc=0

	# cleanup
	stop mds2 || error "cleanup: stop mds2 failed"
	start mds2 $(mdsdevname 2) $MDS_MOUNT_OPTS ||
		error "cleanup: start mds2 failed"
	zconf_mount $(hostname) $MOUNT || error "cleanup: mount failed"
	client_up || error "post-failover df failed"
	all_mds_up
}
run_test 110k "FID_QUERY failed during recovery"

test_110m () {
	(( $(lustre_version_code $SINGLEMDS) >= $(version_code 2.14.52) )) ||
		skip "Need MDS version at least 2.14.52"
	(( $MDSCOUNT >= 2 )) || skip "needs at least 2 MDTs"
	local remote_dir=$DIR/$tdir/remote_dir
	local mdccli
	local uuid
	local diridx

	mkdir_on_mdt0 $DIR/$tdir

#define OBD_FAIL_PTLRPC_RESEND_RACE 0x0525
	do_facet mds1 $LCTL set_param fail_loc=0x80000525
	$LFS mkdir -i 1 -c2 $remote_dir &
	mkdir_pid=$!
	sleep 3
	# initiate the re-connect & re-send
	mdccli=$(do_facet mds2 $LCTL dl |
		awk '/MDT0000-osp-MDT0001/ {print $4;}')
	uuid=$(do_facet mds2 $LCTL get_param -n osp.$mdccli.mdt_conn_uuid)
	echo "conn_uuid=$uuid"
	do_facet mds2 $LCTL set_param "osp.$mdccli.import=connection=$uuid"

	wait $mkdir_pid
	(( $? == 0 )) || error "mkdir failed"

	diridx=$($LFS getstripe -m $remote_dir)
	(( $diridx == 1 )) || error "$diridx != 1"
	rm -rf $DIR/$tdir || error "rmdir failed"
}
run_test 110m "update resent vs original RPC race"

# LU-2844 mdt prepare fail should not cause umount oops
test_111 ()
{
	[[ "$MDS1_VERSION" -ge $(version_code 2.3.62) ]] ||
		skip "Need MDS version at least 2.3.62"

#define OBD_FAIL_MDS_CHANGELOG_INIT 0x151
	do_facet $SINGLEMDS lctl set_param fail_loc=0x151
	stop $SINGLEMDS || error "stop MDS failed"
	start $SINGLEMDS $(mdsdevname ${SINGLEMDS//mds/}) $MDS_MOUNT_OPTS &&
		error "start MDS should fail"
	do_facet $SINGLEMDS lctl set_param fail_loc=0
	start $SINGLEMDS $(mdsdevname ${SINGLEMDS//mds/}) $MDS_MOUNT_OPTS ||
		error "start MDS failed"
}
run_test 111 "mdd setup fail should not cause umount oops"

# LU-793
test_112a() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	do_facet_random_file client $TMP/$tfile 100K ||
		error_noexit "Create random file $TMP/$tfile"

	pause_bulk "cp $TMP/$tfile $DIR/$tfile" $TIMEOUT ||
		error_noexit "Can't pause_bulk copy"

	df $DIR
	# expect cmp to succeed, client resent bulk
	cmp $TMP/$tfile $DIR/$tfile ||
		error_noexit "Wrong data has been written"
	rm $DIR/$tfile ||
		error_noexit "Can't remove file"
	rm $TMP/$tfile
}
run_test 112a "bulk resend while orignal request is in progress"

test_115_read() {
	local fail1=$1
	local fail2=$2

	df $DIR
	dd if=/dev/zero of=$DIR/$tfile bs=4096 count=1
	cancel_lru_locks osc

	# OST_READ       =  3,
	$LCTL set_param fail_loc=$fail1 fail_val=3
	dd of=/dev/null if=$DIR/$tfile bs=4096 count=1 &
	pid=$!
	sleep 1

	set_nodes_failloc "$(osts_nodes)" $fail2

	wait $pid || error "dd failed"
	return 0
}

test_115_write() {
	local fail1=$1
	local fail2=$2
	local error=$3
	local fail_val2=${4:-0}

	df $DIR
	touch $DIR/$tfile

	# OST_WRITE      =  4,
	$LCTL set_param fail_loc=$fail1 fail_val=4
	dd if=/dev/zero of=$DIR/$tfile bs=4096 count=1 oflag=dsync &
	pid=$!
	sleep 1

	df $MOUNT
	set_nodes_failloc "$(osts_nodes)" $fail2 $fail_val2

	wait $pid
	rc=$?
	[ $error -eq 0 ] && [ $rc -ne 0 ] && error "dd error ($rc)"
	[ $error -ne 0 ] && [ $rc -eq 0 ] && error "dd success"
	return 0
}

test_115a() {
	[ "$OST1_VERSION" -lt $(version_code 2.8.50) ] &&
		skip "need at least 2.8.50 on OST"

	#define OBD_FAIL_PTLRPC_LONG_REQ_UNLINK  0x51b
	#define OBD_FAIL_PTLRPC_DROP_BULK	 0x51a
	test_115_read 0x8000051b 0x8000051a
}
run_test 115a "read: late REQ MDunlink and no bulk"

test_115b() {
	[ "$OST1_VERSION" -lt $(version_code 2.8.50) ] &&
		skip "need at least 2.8.50 on OST"

	#define OBD_FAIL_PTLRPC_LONG_REQ_UNLINK  0x51b
	#define OBD_FAIL_OST_ENOSPC              0x215

	# pass $OSTCOUNT for the fail_loc to be caught
	# appropriately by the IO thread
	test_115_write 0x8000051b 0x80000215 1 $OSTCOUNT
}
run_test 115b "write: late REQ MDunlink and no bulk"

test_115c() {
	[ "$OST1_VERSION" -lt $(version_code 2.8.50) ] &&
		skip "need at least 2.8.50 on OST"

	#define OBD_FAIL_PTLRPC_LONG_REPL_UNLINK 0x50f
	#define OBD_FAIL_PTLRPC_DROP_BULK	 0x51a
	test_115_read 0x8000050f 0x8000051a
}
run_test 115c "read: late Reply MDunlink and no bulk"

test_115d() {
	[ "$OST1_VERSION" -lt $(version_code 2.8.50) ] &&
		skip "need at least 2.8.50 on OST"

	#define OBD_FAIL_PTLRPC_LONG_REPL_UNLINK 0x50f
	#define OBD_FAIL_OST_ENOSPC              0x215
	test_115_write 0x8000050f 0x80000215 0
}
run_test 115d "write: late Reply MDunlink and no bulk"

test_115e() {
	[ "$OST1_VERSION" -lt $(version_code 2.8.50) ] &&
		skip "need at least 2.8.50 on OST"

	#define OBD_FAIL_PTLRPC_LONG_BULK_UNLINK 0x510
	#define OBD_FAIL_OST_ALL_REPLY_NET       0x211
	test_115_read 0x80000510 0x80000211
}
run_test 115e "read: late Bulk MDunlink and no reply"

test_115f() {
	[ "$OST1_VERSION" -lt $(version_code 2.8.50) ] &&
		skip "need at least 2.8.50 on OST"

	#define OBD_FAIL_PTLRPC_LONG_REQ_UNLINK  0x51b
	#define OBD_FAIL_OST_ALL_REPLY_NET       0x211
	test_115_read 0x8000051b 0x80000211
}
run_test 115f "read: late REQ MDunlink and no reply"

test_115g() {
	[ "$OST1_VERSION" -lt $(version_code 2.8.50) ] &&
		skip "need at least 2.8.50 on OST"

	#define OBD_FAIL_PTLRPC_LONG_BOTH_UNLINK 0x51c
	test_115_read 0x8000051c 0
}
run_test 115g "read: late REQ MDunlink and Reply MDunlink"

# parameters: fail_loc CMD RC
test_120_reply() {
	local PID
	local PID2
	local rc=5
	local fail

	#define OBD_FAIL_LDLM_CP_CB_WAIT2	0x320
	#define OBD_FAIL_LDLM_CP_CB_WAIT3	0x321
	#define OBD_FAIL_LDLM_CP_CB_WAIT4	0x322
	#define OBD_FAIL_LDLM_CP_CB_WAIT5	0x323

	echo
	echo -n "** FLOCK REPLY vs. EVICTION race, lock $2"
	[ "$1" = "CLEANUP" ] &&
		fail=0x80000320 && echo ", $1 cp first"
	[ "$1" = "REPLY" ] &&
		fail=0x80000321 && echo ", $1 cp first"
	[ "$1" = "DEADLOCK CLEANUP" ] &&
		fail=0x80000322 && echo " DEADLOCK, CLEANUP cp first"
	[ "$1" = "DEADLOCK REPLY" ] &&
		fail=0x80000323 && echo " DEADLOCK, REPLY cp first"

	if [ x"$2" = x"get" ]; then
		#for TEST lock, take a conflict in advance
		# sleep longer than evictor to not confuse fail_loc: 2+2+4
		echo "** Taking conflict **"
		flocks_test 5 set read sleep 10 $DIR/$tfile &
		PID2=$!

		sleep 2
	fi

	$LCTL set_param fail_loc=$fail

	flocks_test 5 $2 write $DIR/$tfile &
	PID=$!

	sleep 2
	echo "** Evicting and re-connecting client **"
	mds_evict_client

	client_reconnect

	if [ x"$2" = x"get" ]; then
		wait $PID2
	fi

	wait $PID
	rc=$?

	# check if the return value is allowed
	[ $rc -eq $3 ] && rc=0

	$LCTL set_param fail_loc=0
	return $rc
}

# a lock is taken, unlock vs. cleanup_resource() race for destroying
# the ORIGINAL lock.
test_120_destroy()
{
	local PID

	flocks_test 5 set write sleep 4 $DIR/$tfile &
	PID=$!
	sleep 2

	# let unlock to sleep in CP CB
	$LCTL set_param fail_loc=$1
	sleep 4

	# let cleanup to cleep in CP CB
	mds_evict_client

	client_reconnect

	wait $PID
	rc=$?

	$LCTL set_param fail_loc=0
	return $rc
}

test_120() {
	flock_is_enabled || { skip "mount w/o flock enabled" && return; }
	touch $DIR/$tfile

	test_120_reply "CLEANUP" set 5 || error "SET race failed"
	test_120_reply "CLEANUP" get 5 || error "GET race failed"
	test_120_reply "CLEANUP" unlock 5 || error "UNLOCK race failed"

	test_120_reply "REPLY" set 5 || error "SET race failed"
	test_120_reply "REPLY" get 5 || error "GET race failed"
	test_120_reply "REPLY" unlock 5 || error "UNLOCK race failed"

	# DEADLOCK tests
	test_120_reply "DEADLOCK CLEANUP" set 5 || error "DEADLOCK race failed"
	test_120_reply "DEADLOCK REPLY" set 35 || error "DEADLOCK race failed"

	test_120_destroy 0x320 || error "unlock-cleanup race failed"
}
run_test 120 "flock race: completion vs. evict"

test_113() {
	local BEFORE=$(date +%s)
	local EVICT

	# modify dir so that next revalidate would not obtain UPDATE lock
	touch $DIR

	# drop 1 reply with UPDATE lock,
	# resend should not create 2nd lock on server
	mcreate $DIR/$tfile || error "mcreate failed: $?"
	drop_mdt_ldlm_reply_once "stat $DIR/$tfile" || error "stat failed: $?"

	# 2 BL AST will be sent to client, both must find the same lock,
	# race them to not get EINVAL for 2nd BL AST
	#define OBD_FAIL_LDLM_PAUSE_CANCEL2      0x31f
	$LCTL set_param fail_loc=0x8000031f

	$LCTL set_param ldlm.namespaces.*.early_lock_cancel=0 > /dev/null
	chmod 0777 $DIR/$tfile || error "chmod failed: $?"
	$LCTL set_param ldlm.namespaces.*.early_lock_cancel=1 > /dev/null

	# let the client reconnect
	client_reconnect
	EVICT=$($LCTL get_param mdc.$FSNAME-MDT*.state |
	  awk -F"[ [,]" '/EVICTED ]$/ { if (mx<$5) {mx=$5;} } END { print mx }')

	[ -z "$EVICT" ] || [[ $EVICT -le $BEFORE ]] || error "eviction happened"
}
run_test 113 "ldlm enqueue dropped reply should not cause deadlocks"

T130_PID=0
test_130_base() {
	test_mkdir -p -c1 $DIR/$tdir
	local mdts=$(mdts_nodes)

	# Prevent interference from layout intent RPCs due to
	# asynchronous writeback. These will be tested in 130c below.
	do_nodes ${CLIENTS:-$HOSTNAME} sync

	# get only LOOKUP lock on $tdir
	cancel_lru_locks mdc
	ls $DIR/$tdir/$tfile 2>/dev/null

	# get getattr by fid on $tdir
	#
	# we need to race with unlink, unlink must complete before we will
	# take a DLM lock, otherwise unlink will wait until getattr will
	# complete; but later than getattr starts so that getattr found
	# the object
#define OBD_FAIL_MDS_INTENT_DELAY		0x160
	set_nodes_failloc $mdts 0x80000160
	stat $DIR/$tdir &
	T130_PID=$!
	sleep 2

	rm -rf $DIR/$tdir

	# drop the reply so that resend happens on an unlinked file.
#define OBD_FAIL_MDS_LDLM_REPLY_NET	 0x157
	set_nodes_failloc $mdts 0x80000157
}

test_130a() {
	remote_mds_nodsh && skip "remote MDS with nodsh"
	[[ "$MDS1_VERSION" -ge $(version_code 2.7.2) ]] ||
		skip "Need server version newer than 2.7.1"

	test_130_base

	wait $T130_PID || [ $? -eq 0 ] && error "stat should fail"
	return 0
}
run_test 130a "enqueue resend on not existing file"

test_130b() {
	remote_mds_nodsh && skip "remote MDS with nodsh"
	[[ "$MDS1_VERSION" -ge $(version_code 2.7.2) ]] ||
		skip "Need server version newer than 2.7.1"

	test_130_base
	# let the reply to be dropped
	sleep 10

#define OBD_FAIL_SRV_ENOENT              0x217
	set_nodes_failloc "$(mdts_nodes)" 0x80000217

	wait $T130_PID || [ $? -eq 0 ] && error "stat should fail"
	return 0
}
run_test 130b "enqueue resend on a stale inode"

test_130c() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	local mdts=$(mdts_nodes)

	do_nodes ${CLIENTS:-$HOSTNAME} sync
	echo XXX > $DIR/$tfile

	cancel_lru_locks mdc

	# Trigger writeback on $tfile.
	#
	# we need to race with unlink, unlink must complete before we will
	# take a DLM lock, otherwise unlink will wait until intent will
	# complete; but later than intent starts so that intent found
	# the object
#define OBD_FAIL_MDS_INTENT_DELAY		0x160
	set_nodes_failloc $mdts 0x80000160
	sync &
	T130_PID=$!
	sleep 2

	rm $DIR/$tfile

	# drop the reply so that resend happens on an unlinked file.
#define OBD_FAIL_MDS_LDLM_REPLY_NET	 0x157
	set_nodes_failloc $mdts 0x80000157

	# let the reply to be dropped
	sleep 10

#define OBD_FAIL_SRV_ENOENT              0x217
	set_nodes_failloc $mdts 0x80000217

	wait $T130_PID

	return 0
}
run_test 130c "layout intent resend on a stale inode"

test_132() {
	local before=$(date +%s)
	local evict

	mount_client $MOUNT2 || error "mount filed"

	rm -f $DIR/$tfile
	# get a lock on client so that export would reach the stale list
	$LFS setstripe -i 0 $DIR/$tfile || error "setstripe failed"
	dd if=/dev/zero of=$DIR/$tfile bs=4096 count=1 conv=fsync ||
		error "dd failed"

	#define OBD_FAIL_OST_PAUSE_PUNCH         0x236
	do_facet ost1 $LCTL set_param fail_val=120 fail_loc=0x80000236

	$TRUNCATE $DIR/$tfile 100 &

	sleep 1
	dd if=/dev/zero of=$DIR2/$tfile bs=4096 count=1 conv=notrunc ||
		error "dd failed"

	wait
	umount_client $MOUNT2

	evict=$(do_facet client $LCTL get_param \
		osc.$FSNAME-OST0000-osc-*/state |
	    awk -F"[ [,]" '/EVICTED ]$/ { if (t<$5) {t=$5;} } END { print t }')

	[ -z "$evict" ] || [[ $evict -le $before ]] ||
		(do_facet client $LCTL get_param \
			osc.$FSNAME-OST0000-osc-*/state;
		    error "eviction happened: $evict before:$before")
}
run_test 132 "long punch"

test_131() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return 0

	rm -f $DIR/$tfile
	# get a lock on client so that export would reach the stale list
	$LFS setstripe -i 0 $DIR/$tfile || error "setstripe failed"
	dd if=/dev/zero of=$DIR/$tfile count=1 || error "dd failed"

	# another IO under the same lock
	#define OBD_FAIL_OSC_DELAY_IO            0x414
	$LCTL set_param fail_loc=0x80000414
	$LCTL set_param fail_val=4 fail_loc=0x80000414
	dd if=/dev/zero of=$DIR/$tfile count=1 conv=notrunc oflag=dsync &
	local pid=$!
	sleep 1

	#define OBD_FAIL_LDLM_BL_EVICT           0x31e
	set_nodes_failloc "$(osts_nodes)" 0x8000031e
	ost_evict_client
	client_reconnect

	wait $pid && error "dd succeeded"
	return 0
}
run_test 131 "IO vs evict results to IO under staled lock"

test_133() {
	local t=$((TIMEOUT * 2))
	touch $DIR/$tfile

	flock $DIR/$tfile -c "echo bl lock;sleep $t;echo bl flock unlocked" &
	sleep 1
	multiop_bg_pause $DIR/$tfile O_jc || return 1
	PID=$!

	#define OBD_FAIL_MDS_LDLM_REPLY_NET 0x157
	do_nodes $(mdts_nodes) $LCTL set_param fail_loc=0x80000157
	kill -USR1 $PID
	echo "waiting for multiop $PID"
	wait $PID || return 2

	rm -f $DIR/$tfile

	return 0
}
run_test 133 "don't fail on flock resend"

test_134() {
	[ $CLIENTCOUNT -lt 2 ] &&
		{ skip "Need 2+ clients, have $CLIENTCOUNT" && return; }

	mkdir -p $MOUNT/$tdir/1 $MOUNT/$tdir/2 || error "mkdir failed"
	touch $MOUNT/$tdir/1/$tfile $MOUNT/$tdir/2/$tfile ||
		error "touch failed"
	zconf_umount_clients $CLIENTS $MOUNT
	zconf_mount_clients $CLIENTS $MOUNT

#define OBD_FAIL_TGT_REPLY_DATA_RACE    0x722
	# assume commit interval is 5
	do_facet mds1 "$LCTL set_param fail_loc=0x722 fail_val=5"

	local -a clients=(${CLIENTS//,/ })
	local client1=${clients[0]}
	local client2=${clients[1]}

	do_node $client1 rm $MOUNT/$tdir/1/$tfile &
	rmpid=$!
	do_node $client2 mv $MOUNT/$tdir/2/$tfile $MOUNT/$tdir/2/${tfile}_2 &
	mvpid=$!
	fail mds1
	wait $rmpid || error "rm failed"
	wait $mvpid || error "mv failed"
	return 0
}
run_test 134 "race between failover and search for reply data free slot"

test_135() {
	[ "$MDS1_VERSION" -lt $(version_code 2.12.51) ] &&
		skip "Need MDS version at least 2.12.51"

	mkdir -p $DIR/$tdir
	$LFS setstripe -E 1M -L mdt $DIR/$tdir
	# to have parent dir write lock before open/resend
	touch $DIR/$tdir/$tfile
	#define OBD_FAIL_MDS_LDLM_REPLY_NET 0x157
	do_nodes $(mdts_nodes) "$LCTL set_param fail_loc=0x80000157"
	openfile -f O_RDWR:O_CREAT -m 0755 $DIR/$tdir/$tfile ||
		error "Failed to open DOM file"
}
run_test 135 "DOM: open/create resend to return size"

test_136() {
	remote_mds_nodsh && skip "remote MDS with nodsh"
	[[ "$MDS1_VERSION" -ge $(version_code 2.12.52) ]] ||
		skip "Need MDS version at least 2.12.52"

	local mdts=$(comma_list $(mdts_nodes))
	local MDT0=$(facet_svc $SINGLEMDS)

	local clog=$(do_facet mds1 $LCTL --device $MDT0 changelog_register -n)
	[ -n "$clog" ] || error "changelog_register failed"
	cl_mask=$(do_facet mds1 $LCTL get_param \
				mdd.$MDT0.changelog_mask -n)
	changelog_chmask "ALL"

	# generate some changelog records to accumulate
	test_mkdir -i 0 -c 0 $DIR/$tdir || error "mkdir $tdir failed"
	createmany -m $DIR/$tdir/$tfile 10000 ||
		error "create $DIR/$tdir/$tfile failed"

	local size1=$(do_facet $SINGLEMDS \
		      $LCTL get_param -n mdd.$MDT0.changelog_size)
	echo "Changelog size $size1"

	#define OBD_FAIL_LLOG_PURGE_DELAY		    0x1318
	do_nodes $mdts $LCTL set_param fail_loc=0x1318 fail_val=30

	# launch changelog_deregister in background on MDS
	do_facet mds1 "nohup $LCTL --device $MDT0 changelog_deregister $clog \
			> foo.out 2> foo.err < /dev/null &"
	# give time to reach fail_loc
	sleep 15

	# fail_loc will make MDS sleep in the middle of changelog_deregister
	# take this opportunity to abruptly kill MDS
	FAILURE_MODE_save=$FAILURE_MODE
	FAILURE_MODE=HARD
	fail mds1
	FAILURE_MODE=$FAILURE_MODE_save

	do_nodes $mdts $LCTL set_param fail_loc=0x0 fail_val=0

	local size2=$(do_facet $SINGLEMDS \
		      $LCTL get_param -n mdd.$MDT0.changelog_size)
	echo "Changelog size $size2"
	local clog2=$(do_facet $SINGLEMDS "$LCTL get_param -n \
			mdd.$MDT0.changelog_users | grep $clog")
	echo "After crash, changelog user $clog2"

	[ -n "$clog2" -o $size2 -lt $size1 ] ||
		error "changelog record count unchanged"

	do_facet mds1 $LCTL set_param mdd.$MDT0.changelog_mask=\'$cl_mask\' -n
}
run_test 136 "changelog_deregister leaving pending records"

test_137() {
	df $DIR
	mkdir_on_mdt0 $DIR/$tdir
	mkdir $DIR/$tdir/d1
	mkdir $DIR/$tdir/d2
	dd if=/dev/zero of=$DIR/$tdir/d1/$tfile bs=4096 count=1
	dd if=/dev/zero of=$DIR/$tdir/d2/$tfile bs=4096 count=1
	cancel_lru_locks osc

	#define OBD_FAIL_PTLRPC_RESEND_RACE	 0x525
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000525"

	# RPC1: any reply is to be delayed to disable last_xid logic
	ln $DIR/$tdir/d1/$tfile $DIR/$tdir/d1/f2 &
	sleep 1

	# RPC2: setattr1 reply is delayed & resent
	# original reply comes to client; the resend get asleep
	chmod 666 $DIR/$tdir/d2/$tfile

	# RPC3: setattr2 on the same file; run ahead of RPC2 resend
	chmod 777 $DIR/$tdir/d2/$tfile

	# RPC2 resend wakes up
	sleep 5
	[ $(stat -c "%a" $DIR/$tdir/d2/$tfile) == 777 ] ||
		error "resend got applied"
}
run_test 137 "late resend must be skipped if already applied"

test_138() {
	remote_mds_nodsh && skip "remote MDS with nodsh"
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	[[ "$MDS1_VERSION" -ge $(version_code 2.12.59) ]] ||
		skip "Need server version newer than 2.12.59"

	zconf_umount_clients $CLIENTS $MOUNT

#define OBD_FAIL_TGT_RECOVERY_CONNECT 0x724
	#delay a first step of recovey when MDS waiting clients
	#and failing to get osp logs
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x724 fail_val=5

	facet_failover $SINGLEMDS

	#waiting failover and recovery timer
	#the valuse is based on target_recovery_overseer() wait_event timeout
	sleep 55
	stop $SINGLEMDS || error "stop MDS failed"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	start $SINGLEMDS $(mdsdevname ${SINGLEMDS//mds/}) $MDS_MOUNT_OPTS ||
		error "start MDS failed"
	zconf_mount_clients $CLIENTS $MOUNT
}
run_test 138 "Umount MDT during recovery"

test_139() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	[ $MDS1_VERSION -lt $(version_code 2.13.50) ] &&
		skip "Need MDS version at least 2.13.50"

	stop $SINGLEMDS || error "stop $SINGLEMDS failed"

#define OBD_FAIL_OSP_INVALID_LOGID		0x2106
	do_facet $SINGLEMDS $LCTL set_param fail_val=0x68 fail_loc=0x80002106
	start $SINGLEMDS $(mdsdevname ${SINGLEMDS//mds/}) $MDS_MOUNT_OPTS ||
		error "Fail to start $SINGLEMDS"
}
run_test 139 "corrupted catid won't cause crash"

test_140a() {
	[ $MDS1_VERSION -lt $(version_code 2.12.58) ] &&
		skip "Need MDS version at least 2.13.50"

	slr=$(do_facet mds1 \
		$LCTL get_param -n mdt.$FSNAME-MDT0000.local_recovery)
	stack_trap "do_facet mds1 $LCTL set_param \
		mdt.*.local_recovery=$slr" EXIT

	# disable recovery for local clients
	# so local clients should be marked with no_recovery flag
	do_facet mds1 $LCTL set_param mdt.*.local_recovery=0
	mount_mds_client

	local cnt
	cnt=$(do_facet mds1 $LCTL get_param "mdt.*MDT0000.exports.*.export" |
		grep export_flags.*no_recovery | wc -l)
	echo "$cnt clients with recovery disabled"
	umount_mds_client
	[ $cnt -eq 0 ] && error "no clients with recovery disabled"

	# enable recovery for local clients
	# so no local clients should be marked with no_recovery flag
	do_facet mds1 $LCTL set_param mdt.*.local_recovery=1
	mount_mds_client

	cnt=$(do_facet mds1 $LCTL get_param "mdt.*MDT0000.exports.*.export" |
		grep export_flags.*no_recovery | wc -l)
	echo "$cnt clients with recovery disabled"
	umount_mds_client
	[ $cnt -eq 0 ] || error "$cnt clients with recovery disabled"
}
run_test 140a "local mount is flagged properly"

test_140b() {
	[ $MDS1_VERSION -lt $(version_code 2.12.58) ] &&
		skip "Need MDS version at least 2.13.50"

	slr=$(do_facet mds1 \
		$LCTL get_param -n mdt.$FSNAME-MDT0000.local_recovery)
	stack_trap "do_facet mds1 $LCTL set_param \
		mdt.*.local_recovery=$slr" EXIT

	# disable recovery for local clients
	do_facet mds1 $LCTL set_param mdt.*.local_recovery=0

	mount_mds_client
	replay_barrier mds1
	umount_mds_client
	fail mds1
	# Lustre: tfs-MDT0000: Recovery over after 0:03, of 2 clients 2 rec...
	local recovery=$(do_facet mds1 dmesg |
			 awk '/Recovery over after/ { print $6 }' | tail -1 |
			 awk -F: '{ print $1 * 60 + $2 }')
	(( recovery < TIMEOUT * 2 + 5 )) ||
		error "recovery took too long $recovery > $((TIMEOUT * 2 + 5))"
}
run_test 140b "local mount is excluded from recovery"

test_141() {
	local oldc=0
	local newc
	local oldgen

	[ "$PARALLEL" == "yes" ] && skip "skip parallel run"
	combined_mgs_mds || skip "needs combined MGS/MDT"
	( local_mode || from_build_tree ) &&
		skip "cannot run in local mode or from build tree"

	# some get_param have a bug to handle dot in param name
	oldgen=$(do_facet ost1 $LCTL get_param -n mgc.*.import |
		 awk '/generation:/{print $NF}')
	do_rpc_nodes $(facet_active_host ost1) cancel_lru_locks MGC
	local end=$((SECONDS + 30))
	local tmpc=1

	while (( oldc == 0 || tmpc != oldc )) && (( SECONDS < end )); do
		tmpc=$oldc
		sleep 1
		oldc=$(do_facet ost1 \
		       $LCTL "get_param -n 'ldlm.namespaces.MGC*.lock_count'")
	done

	fail $SINGLEMDS
	wait_mgc_import_state ost1 FULL
	wait_update_facet_cond ost1 "$LCTL get_param -n mgc.*.import |
		awk '/generation:/{print}' | cut -d':' -f2" "!=" " $oldgen"
	do_rpc_nodes $(facet_active_host ost1) cancel_lru_locks MGC
	wait_update_facet ost1 \
		"$LCTL get_param -n 'ldlm.namespaces.MGC*.lock_count'" $oldc ||
	{
		newc=$(do_facet ost1 \
		       $LCTL get_param -n 'ldlm.namespaces.MGC*.lock_count')
		error "mgc lost locks ($oldc != $newc)"
	}
}
run_test 141 "do not lose locks on MGS restart"

test_142() {
	[ $MDS1_VERSION -lt $(version_code 2.11.56) ] &&
		skip "Need MDS version at least 2.11.56"

	#define OBD_FAIL_MDS_ORPHAN_DELETE	0x165
	do_facet mds1 $LCTL set_param fail_loc=0x165
	$MULTIOP $DIR/$tfile Ouc || error "multiop failed"

	stop mds1
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS

	wait_update_facet mds1 "pgrep orph_.*-MDD | wc -l" "0" ||
		error "MDD orphan cleanup thread not quit"
}
run_test 142 "orphan name stub can be cleaned up in startup"

test_143() {
	(( $MDS1_VERSION >= $(version_code 2.13.0) )) ||
		skip "Need MDS version at least 2.13.0"
	[ "$PARALLEL" == "yes" ] && skip "skip parallel run"

	local mntpt=$(facet_mntpt $SINGLEMDS)
	stop mds1
	mount_fstype $SINGLEMDS || error "mount as fstype $SINGLEMDS failed"
	do_facet $SINGLEMDS touch $mntpt/PENDING/$tfile
	unmount_fstype $SINGLEMDS
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS || error "mds1 start fail"

	wait_recovery_complete $SINGLEMDS || error "MDS recovery not done"
	wait_update_facet mds1 "pgrep orph_.*-MDD | wc -l" "0" ||
		error "MDD orphan cleanup thread not quit"
}
run_test 143 "orphan cleanup thread shouldn't be blocked even delete failed"

test_144a() {
	[[ $($LCTL get_param mdc.*.import) =~ connect_flags.*overstriping ]] ||
		skip "server does not support overstriping"
	(( MDS1_VERSION >= $(version_code 2.15.50.49) )) ||
		skip "Need MDS version at least 2.15.50.49"

	local pids=""
	local setcount=1000
	local mds_timeout
	local before
	local after
	local diff
	local mdts=$(mdts_nodes)

	large_xattr_enabled || skip_env "ea_inode feature disabled"
	test_mkdir -i 0 -c 1 -p $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir" EXIT

	mds_timeout=$(do_facet mds1 $LCTL get_param -n timeout)
	do_nodes $mdts "$LCTL set_param timeout=300"
	stack_trap "do_nodes $mdts $LCTL set_param timeout=$mds_timeout"

	$LFS setstripe -i 0 -C $setcount $DIR/$tdir || error "setstripe failed"

	for (( i = 0; i < 50; i++)); do
		touch $DIR/$tdir/$tfile_$i &
		pids="$pids $!"
	done

	fail ost1
	sleep 60

	for pid in $pids; do
		kill -9 $pid >/dev/null 2>&1
	done

	before=$SECONDS
	fail mds1
	after=$SECONDS
	# here we measure MDT stop + MDT start time. For error case MDT stop takes
	# about obd_timeout-60 (240) seconds. Without error - less than 30s.
	# MDT start takes different time depends on a configuration, let's check
	# the worst.
	diff=$((after - before))
	(( $diff < 240 )) || error "MDT failover took $diff seconds"

	# failover mds1 back to the primary server
	fail mds1
}
run_test 144a "MDT failover should stop precreation threads"

test_144b() {
	[[ $($LCTL get_param mdc.*.import) =~ connect_flags.*overstriping ]] ||
		skip "server does not support overstriping"
	(( MDS1_VERSION >= $(version_code 2.15.51.50) )) ||
		skip "Need MDS version at least 2.15.51.50"

	local pids=""
	local rc=0
	local setcount=1000
	local mds_timeout
	local mdts=$(mdts_nodes)

	large_xattr_enabled || skip_env "ea_inode feature disabled"
	test_mkdir -i 0 -c 1 -p $DIR/$tdir
	stack_trap "rm -rf $DIR/$tdir" EXIT

	mds_timeout=$(do_facet mds1 $LCTL get_param -n timeout)
	do_nodes $mdts "$LCTL set_param timeout=300"
	stack_trap "do_nodes $mdts $LCTL set_param timeout=$mds_timeout"

	$LFS setstripe -i 0 -C $setcount $DIR/$tdir || error "setstripe failed"

	for (( i = 0; i < 50; i++)); do
		touch $DIR/$tdir/$tfile_$i &
		pids="$pids $!"
	done

	fail ost1

	# 60s is not enought with ZFS which is still significatnly
	# slower on some operations like record writing
	local stime=60
	[[ "$mds1_FSTYPE" != "zfs" ]] || stime=120
	sleep $stime

	for pid in $pids; do
		ps -p $pid > /dev/null
		(( $? == 0 )) && rc=1
		kill -9 $pid >/dev/null 2>&1
	done
	echo "rc $rc"
	(( $rc == 0 )) || { fail mds1; error "Create thread still running"; }
}
run_test 144b "orphan cleanup shouldn't be blocked for no objects+failover situation"

test_144c() {
	[ "$PARALLEL" == "yes" ] && skip "skip parallel run"
	remote_mds_nodsh && skip "remote MDS with nodsh"
	remote_ost_nodsh && skip "remote OST with nodsh"
	 (( OST1_VERSION >= $(version_code 2.15.59.53) )) ||
		skip "need OSS >= v2_15_59.53 for reconnect fix"
	local rc

	#increase a precreation window
	mkdir_on_mdt0 $DIR/$tdir
	$LFS setstripe -c 1 -i 0 $DIR/$tdir
	createmany -o $DIR/$tdir/$tfile 9000

	stop mds1
#define OBD_FAIL_OST_DELORPHAN_DELAY     0x254
	#delay delorphan request to reconnection 5seconds
	do_facet ost1 $LCTL set_param fail_loc=0x0000254 fail_val=5

	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS || error "mds1 start fail"

	wait_recovery_complete mds1 || error "MDS recovery not done"

	sleep 1
	#reconnect
	do_facet mds1 $LCTL --device $FSNAME-OST0000-osc-MDT0000 recover

	do_facet ost1 $LCTL set_param fail_loc=0 fail_val=0

	#first and second orphan request delayed for 5seconds
	sleep 12

	local testid=${TESTNAME//_/ }

	do_facet ost1 "dmesg | tac | sed '/$testid/,$ d'" |
		grep "trust the OST"
	rc=$?
	if (( rc == 0 )); then
		remount_facet mds1
		error "LAST_ID synchronization failed"
	else
		return 0
	fi
}
run_test 144c "reconnection during orphan cleanup shouldn't lose LAST_ID synchronization"

test_145() {
	[ $MDSCOUNT -lt 3 ] && skip "needs >= 3 MDTs"
	[ $(facet_active_host mds2) = $(facet_active_host mds3) ] &&
		skip "needs mds2 and mds3 on separate nodes"

	replay_barrier mds1

	touch $DIR/$tfile

#define OBD_FAIL_PTLRPC_DELAY_RECOV      0x507
	echo block mds_connect from mds2
	do_facet mds2 "$LCTL set_param fail_loc=0x507"

#define OBD_FAIL_OUT_UPDATE_DROP	0x1707
	echo block recovery updates from mds3
	do_facet mds3 "$LCTL set_param fail_loc=0x1707"

	local hard_timeout=\
$(do_facet mds1 $LCTL get_param -n mdt.$FSNAME-MDT0000.recovery_time_hard)

	fail mds1 &

	local get_soft_timeout_cmd=\
"$LCTL get_param -n mdt.$FSNAME-MDT0000.recovery_time_soft 2>/dev/null"

	echo wait until mds1 recovery_time_soft is $hard_timeout
	wait_update $(facet_host mds1) "$get_soft_timeout_cmd" \
"$hard_timeout" $hard_timeout

	echo unblock mds_connect from mds2
	do_facet mds2 "$LCTL set_param fail_loc=0"

	echo upblock recovery updates from mds3
	do_facet mds3 "$LCTL set_param fail_loc=0"

	wait
	[ -f $DIR/$tfile ] || error "$DIR/$tfile does not exist"
}
run_test 145 "connect mdtlovs and process update logs after recovery expire"

test_146() {
	(( $MDS1_VERSION >= $(version_code 2.15.54.6) )) ||
		skip "Need MDS >= v2_15_54-6-g3c69d46e17 for eviction_count"

	local prev_count=$(do_facet $SINGLEMDS \
		$LCTL get_param -n "mdt.${mds1_svc}.eviction_count")

	mds_evict_client

	client_reconnect

	local next_count=$(do_facet $SINGLEMDS \
		$LCTL get_param -n "mdt.${mds1_svc}.eviction_count")

	[ "$prev_count" -lt "$next_count" ] ||
		error "wrong eviction count ($prev_count >= $next_count)"
}
run_test 146 "test eviction is counted properly"

test_147() {
	local obd_timeout=200
	local old=$($LCTL get_param -n timeout)
	local f=$DIR/$tfile
	local connection_count

	$LFS setstripe -i 0 -c 1 $f
	stripe_index=$($LFS getstripe -i $f)
	if [ $stripe_index -ne 0 ]; then
	       $LFS getstripe $f
	       error "$f: stripe_index $stripe_index != 0" && return
	fi

	$LCTL set_param timeout=$obd_timeout
	stack_trap "$LCTL set_param timeout=$old && client_reconnect" EXIT

	# OBD_FAIL_OST_CONNECT_NET2
	# lost reply to connect request
	do_facet ost1 lctl set_param fail_loc=0x00000225 timeout=$obd_timeout
	stack_trap "do_facet ost1 $LCTL set_param fail_loc=0 timeout=$old" EXIT


	ost_evict_client
	# force reconnect
	$LFS df $MOUNT > /dev/null 2>&1 &
	sleep $((obd_timeout * 3 / 4))

	$LCTL get_param osc.$FSNAME-OST0000-osc-*.state
	connection_count=$($LCTL get_param osc.$FSNAME-OST0000-osc-*.state |
			   tac |  sed "/FULL/,$ d" | grep CONNECTING | wc -l)

	echo $connection_count
	(($connection_count >= 6)) || error "Client reconnected too slow"
}
run_test 147 "Check client reconnect"

test_148() {
	local wce_param="obdfilter.$FSNAME-OST0000.writethrough_cache_enable"
	local p="$TMP/$TESTSUITE-$TESTNAME.parameters"
	local amc=$(at_max_get client)
	local amo=$(at_max_get ost1)
	local timeout

	at_max_set 0 client
	at_max_set 0 ost1
	timeout=$(request_timeout client)

	[ "$(facet_fstype ost1)" = "ldiskfs" ] && {
		# save old r/o cache settings
		save_lustre_params ost1 $wce_param > $p

		# disable r/o cache
		do_facet ost1 "$LCTL set_param -n $wce_param=0"
	}

	$LFS setstripe -i 0 -c 1 $DIR/$tfile
	dd if=/dev/zero of=$DIR/$tfile bs=4096 count=1 oflag=direct
	cp $DIR/$tfile $TMP/$tfile
	#define OBD_FAIL_OST_BRW_PAUSE_BULK2     0x227
	do_facet ost1 $LCTL set_param fail_loc=0x80000227
	do_facet ost1 $LCTL set_param fail_val=$((timeout+2))
	dd if=/dev/urandom of=$DIR/$tfile bs=4096 count=1 conv=notrunc,fdatasync
	dd if=/dev/zero of=$DIR/$tfile bs=4096 count=1 conv=notrunc,fdatasync
	sleep 2
	cancel_lru_locks osc
	cmp -b $DIR/$tfile $TMP/$tfile || error "wrong data"

	rm -f $DIR/$tfile $TMP/$tfile

	at_max_set $amc client
	at_max_set $amo ost1

	[ "$(facet_fstype ost1)" = "ldiskfs" ] && {
		# restore initial r/o cache settings
		restore_lustre_params < $p
	}

	return 0
}
run_test 148 "data corruption through resend"

test_149() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"

	test_mkdir -i 0 -c $MDSCOUNT $DIR/$tdir || error "mkdir $tdir failed"

	# make an orphan striped dir
	$MULTIOP $DIR/$tdir D_c &
	local PID=$!
	sleep 0.3
	rmdir $DIR/$tdir || error "can't rmdir"

	# stop a slave MDT where one ons stripe is located
	stop mds2 -f

	# stopping should not cause orphan as another MDT can
	# be stopped yet
	stop mds1 -f

	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS || error "mds1 start fail"
	start mds2 $(mdsdevname 2) $MDS_MOUNT_OPTS || error "mds1 start fail"

	kill -USR1 $PID
	wait $PID

	clients_up
	return 0
}
run_test 149 "skip orphan removal at umount"

test_150() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	local lazystatfs
	local max

	lazystatfs=$($LCTL get_param -n llite.$FSNAME-*.lazystatfs | head -1)
	max=$($LCTL get_param -n llite.$FSNAME-*.statahead_max | head -1)

	$LCTL set_param llite.$FSNAME-*.lazystatfs=1
	$LCTL set_param llite.$FSNAME-*.statahead_max=0
	stack_trap "$LCTL set_param llite.$FSNAME-*.lazystatfs=$lazystatfs" EXIT
	stack_trap "$LCTL set_param llite.$FSNAME-*.statahead_max=$max" EXIT
	# stop a slave MDT where one ons stripe is located
	stop mds1

	stack_trap "start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS && \
		wait_recovery_complete mds1 && clients_up && true" EXIT

	df $MOUNT || error "statfs failed"
	return 0
}
run_test 150 "statfs when MDT0 offline with lazystatfs option"

test_152() {
	[[ $($LCTL get_param mdc.*.import) =~ connect_flags.*overstriping ]] ||
		skip "server does not support overstriping"

	local before
	local after
	local diff
	local saved
	local version
	local pids_rr=""
	local pids_qos=""
	local setcount=500

	large_xattr_enabled || skip_env "ea_inode feature disabled"
	version=$(do_facet mds1 \
		  uname -r | sed -e "s/\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/")
	version=$(version_code ${version//\./ })
	if (( $version < $(version_code 4.6.0) )); then
		skip "MDS Linux kernel does not support killable semaphore"
	fi

	test_mkdir -i 0 -c 1 -p $DIR/$tdir
	test_mkdir -i 0 -c 1 -p $DIR/$tdir/rr
	test_mkdir -i 0 -c 1 -p $DIR/$tdir/qos
	stack_trap "rm -rf $DIR/$tdir" EXIT

	$LFS setstripe -C $setcount $DIR/$tdir/rr/ || error "setstripe failed"


	#define OBD_FAIL_MDS_LOD_CREATE_PAUSE	 0x173
	#Simulate OST failover and sleep RR allocation under lq_rw_sem
	do_facet mds1 $LCTL set_param fail_loc=0x80000173 fail_val=20
	before=$(date +%s)
	for (( i = 0; i < 2; i++)); do
		touch $DIR/$tdir/rr/$tfile_$i &
		pids_rr="$pids_rr $!"
	done
	sleep 3

	saved=$(do_facet mds1 $LCTL get_param -n lov.*0000*.qos_threshold_rr)
	do_facet mds1 $LCTL set_param lov.*.qos_threshold_rr=0
	stack_trap "do_facet mds1 $LCTL set_param lov.*.qos_threshold_rr=$saved" EXIT

	#create files with QoS algo, killable semaphore sleeps for 2seconds
	for (( i = 0; i < 3; i++)); do
		touch $DIR/$tdir/qos/$tfile_$i &
		pids_qos="$pids_qos $!"
	done

	for pid in $pids_qos; do
		wait $pid
	done
	after=$(date +%s)

	diff=$((after - before))
	echo "QoS allocation took $diff seconds"
	for pid in $pids_rr; do
	       wait $pid
	done

	(( $diff < 20 )) ||
	error "QoS allocation slower than RR, killable semaphore doesn't work"
}
run_test 152 "QoS object allocation could be awakened in case of OST failover"

test_153() {
	(( MDS1_VERSION >= $(version_code 2.15.54.113) )) ||
		skip "need MDS >= v2_15_54-113-g654d5f3fa4df for reconnect fix"

#define OBD_FAIL_MDS_CONNECT_VS_EVICT   0x174
	do_facet mds1 "$LCTL set_param fail_loc=0x174"
	# first drop ping reply from MDS and then
	# evict on the subsequent reconnect
	# (see target_handle_connect)
	sleep $((TIMEOUT + 3))
	stop mds1
	do_facet mds1 "$LCTL set_param fail_loc=0"
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS ||
		error "Fail to start $SINGLEMDS"
	wait_recovery_complete mds1 || error "MDS recovery not done"
}
run_test 153 "evict vs reconnect race"

test_154a() {
	(( MDS1_VERSION >= $(version_code 2.15.60.2) )) ||
		skip "need MDS >= v2_15_60-2-ge81805244476 for llog fix"
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"

	stop mds2

	local mnt=$(facet_mntpt mds2)

	mount_fstype mds2
	local ula=($(do_facet mds2 od -t u8 $mnt/update_log | \
		awk '{ if($2 > 0) printf "0x%x:0x%x:0x0 ", $3, $2  }'))
	[ ${#ula[@]} -lt 2 ] && error "update_log file corruption"

	local catfile=$mnt/update_log_dir/\[${ula[0]}\]

	echo replace file $catfile
	do_facet mds2 dd if=/dev/urandom of=$catfile count=100 ||
		error "Write file $catfile error"
	unmount_fstype mds2

	start mds2 $(mdsdevname 2) $MDS_MOUNT_OPTS || error "mds2 start fail"

	stop mds1
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS || error "mds1 start fail"

	echo waiting mds1 recovery....
	wait_recovery_complete mds1 20

	do_facet mds1 $LCTL get_param mdt.$FSNAME-MDT0000.recovery_status | \
		grep -w COMPLETE || error "Recovery was blocked"
}
run_test 154a "corruption update llog can be skipped"

test_154b() {
	(( MDS1_VERSION >= $(version_code 2.15.60.2) )) ||
		skip "need MDS >= v2_15_60-2-ge81805244476 for llog fix"
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"

	stop mds1

	stack_trap "do_facet mds1 $LCTL set_param fail_loc=0"
#define OBD_FAIL_TGT_RECOVERY_CONNECT 0x724
	do_facet mds1 $LCTL set_param fail_loc=0x0724 fail_val=5
	local OPTS="$MDS_MOUNT_OPTS -o abort_recov"
	start mds1 $(mdsdevname 1) $OPTS ||
		error "start MDS with abort_recovery failed"

	echo waiting mds1 recovery....
	wait_recovery_complete mds1 30
	do_facet mds1 $LCTL get_param mdt.$FSNAME-MDT0000.recovery_status | \
		grep -w COMPLETE || error "Recovery was blocked"

	mount_client $MOUNT2
	umount_client $MOUNT2
	remount_client $MOUNT
}
run_test 154b "restore update llog after failed recovery"

test_155() {
	(( MDS1_VERSION >= $(version_code 2.15.58.110) )) ||
		skip "need MDS >= v2_15_58-110-g71f8e5d6506f for ptlrpc fix"

	local lsoutput1
	local lsoutput2

	touch $DIR/$tfile
	lsoutput1=$(ls -l $DIR)

	zconf_umount $HOSTNAME $MOUNT || error "umount failed"
	# make sure that last_rcvd update is committed
	do_facet mds1 sync
	zconf_mount $HOSTNAME $MOUNT || error "mount failed"

	replay_barrier_nosync mds1

	fail_nodf mds1

	lsoutput2=$(ls -l $DIR) || error "ls failed"
	[[ $lsoutput1 == $lsoutput2 ]] || error "$lsoutput1 != $lsoutput2"
}
run_test 155 "failover after client remount"

test_156()
{
	(( OST1_VERSION >= $(version_code v2_15_60-90-g9df01eee75) )) ||
		skip "Need OST >= 2.15.60.90 for tot_granted miscount fix"

	# on failover recovery time hard will be 9 * 5
	local saved_timeout=$(do_facet ost1 $LCTL get_param -n timeout)

	do_facet mgs $LCTL set_param -P timeout=5 ||
		error "failed to set obd_timeout"
	stack_trap "do_facet mgs $LCTL set_param -P timeout=$saved_timeout" \
	    EXIT

	$LFS setstripe -c 1 -i 0 $DIR/$tfile || error "setstripe failed"

	# this is to sync last_rcvd, so that the client will have to
	# send replay on recovery
	$LFS df $MOUNT
	do_facet ost1 sync

	replay_barrier ost1

	$MULTIOP $DIR/$tfile oO_RDWR:O_SYNC:w1048576c || error "multiop failed"

	# delay write replay for 45 sec (OBD_RECOVERY_TIME_HARD) to
	# get the client evicted as not sending replays

#define OBD_FAIL_PTLRPC_REPLAY_PAUSE	 0x536
	$LCTL set_param fail_loc=0x80000536 fail_val=45

	fail ost1

	# check that ost1 evicted the client in recovery
	local clients
	clients=($(do_facet ost1 \
		$LCTL get_param -n obdfilter.$FSNAME-OST0000.recovery_status |
		awk '/completed_clients/ { print $2 }' | tr '/' '\n'))
	[[ $((${clients[0]} + 1)) == ${clients[1]} ]] ||
		error "client not evicted by ost1"

	local testid=$(echo $TESTNAME | tr '_' ' ')
	do_facet ost1 dmesg | tac | sed "/$testid/,$ d" |
		grep "ofd_obd_disconnect: tot_granted" &&
		error "grant miscount" || true
}
run_test 156 "tot_granted miscount after client eviction"

test_157()
{
	(( MDS1_VERSION >= $(version_code 2.15.58.110) )) ||
		skip "need MDS >= v2_15_58-110-g71f8e5d6506f to avoid eviction"

	$LFS setstripe -i 0 -c 1 $DIR/$tfile || error "setstripe failed"
	dd if=/dev/zero of=$DIR/$tfile bs=4096 count=1
	cancel_lru_locks osc

#define OBD_FAIL_LLITE_FAULT_PAUSE                 0x1432
	$LCTL set_param fail_loc=0x80001432 fail_val=3
	$MULTIOP $DIR/$tfile soO_RDWR:MRUc &
	MULTIPID=$!
	sleep 1
	ost_evict_client
	wait $MULTIPID
	local rc=$?
	(( rc == 0 || rc == 135 )) ||
		error "multiop failed with $rc, not SIGBUS (135)"
}
run_test 157 "eviction during mmaped i/o"

cleanup_158() {
	do_facet mds2 $LCTL set_param fail_loc=0
	zconf_umount_clients $CLIENTS $MOUNT
	mountcli
}

test_158a() {
	(( $MDS1_VERSION >= $(version_code 2.15.62) )) ||
		skip "Need MDS version at least 2.15.62 for -EACCES fix"
	(( MDSCOUNT > 1 )) || skip "needs >= 2 MDTS"

	remount_client $MOUNT
	# ensure there is no MOUNT2 on clients
	zconf_umount_clients $CLIENTS $MOUNT2 -f

	stack_trap cleanup_158 EXIT RETURN

	# client import is evicted after failover followed by -EACCES
	#define OBD_FAIL_MDS_CONNECT_ACCESS	0x2402
	do_facet mds2 $LCTL set_param fail_loc=0x2402
	fail_nodf mds2
	sleep 5
	$LFS df $MOUNT
	do_facet mds2 $LCTL set_param fail_loc=0
	wait_recovery_complete mds2 || error "MDS recovery not done"
	sleep 5

	local mdc2=$($LCTL dl | awk '/mdc.*MDT0001-mdc*/ { print $4}')
	local active=$($LCTL get_param -n mdc.$mdc2.active)
	(( active == 0 )) || error "import status is 'active'"
	$LCTL --device $mdc2 activate
	active=$($LCTL get_param -n mdc.$mdc2.active)
	(( active == 1 )) || error "import status is not 'active'"
	status=$($LFS check mdts | grep $mdc2 | grep -c active)
	(( status == 1 )) || {
		$LFS check mdts
		error "import is not operational"
	}
}
run_test 158a "connect without access right"

test_160() {
	(( $MDS1_VERSION >= $(version_code 2.15.62) )) ||
		skip "Need MDS version at least 2.15.62 for group lock destroy fix"

	local threads=10
	local size=$((1024*100))
	local timeout=10
	local pids

	test_mkdir -i 0 -c 1 $DIR/$tdir
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	for ((i = 1; i <= threads; i++)); do
		local file=$DIR/$tdir/file_$i
		#open/group lock/write/unlink/pause/group unlock/close
		$MULTIOP $file OG1234w10240u_g1234c &
		pids[$i]=$!
	done
	sleep 2

	#evict client from MDS, MDS starts to unlink files/destroy objects
	mds_evict_client
	client_reconnect

	wait_update_facet_cond --verbose mds1 \
		"$LCTL get_param -n osp.$FSNAME-OST0000-osc-MDT0000.destroys_in_flight" \
		"-le" "2" $((timeout * 3))
	local rc=$?
	do_facet mds1 $LCTL get_param osp.$FSNAME-OST0000-osc-MDT0000.error_list
	for ((i = 1; i <= threads; i++)); do
		kill -USR1 ${pids[$i]} && wait ${pids[$i]}
	done

	(( rc == 0 )) || error "destroying OST objects are blocked"

	#without group lock, wait and check if all objects are destroyed
	sleep $((timeout * 3))
	do_facet mds1 $LCTL get_param osp.$FSNAME-OST0000-osc-MDT0000.error_list
	local errs=$(do_facet mds1 $LCTL get_param -n osp.$FSNAME-OST0000-osc-MDT0000.error_list | wc -l)
	rc=$(do_facet mds1 $LCTL get_param -n osp.$FSNAME-OST0000-osc-MDT0000.destroys_in_flight)

	(( $errs == 0 )) || error "error_list not empty"
	(( $rc == 0 )) || error "$rc destroys in flight"
}
run_test 160 "MDT destroys are blocked by grouplocks"

test_161() {
	[[ $MDSCOUNT -lt 2 ]] && skip_env "needs >= 2 MDTs"
	local ping_interval=$($LCTL get_param -n ping_interval)
	local evict_multiplier=$($LCTL get_param -n evict_multiplier)
	local pause=$((ping_interval * (evict_multiplier + 2)))

	#define OBD_FAIL_OBD_PAUSE_EVICTOR	    0x60f
	do_facet mds1 $LCTL set_param fail_loc=0x8000060f

	$LFS mkdir -i 1 $DIR/$tdir || error "mkdir $tdir"
	$LFS mkdir -i 0 $DIR/$tdir/remote || error "mkdir $tdir/remote"

	echo sleep $pause seconds
	sleep $pause
	rmdir $DIR/$tdir/remote || error "rmdir $tdir/remote"
}
run_test 161 "evict osp by ping evictor"

test_162() {
	local mntpt=$(facet_mntpt $SINGLEMDS)

	test_mkdir -i 0 -c 1 $DIR/$tdir
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	local wfile=$DIR/$tdir/$tfile
	local rstr="aAdDiPST"

	stack_trap "chattr -$rstr $wfile; rm -rf $DIR/$tdir" EXIT

	touch $wfile
	for ((i = 0; i < ${#rstr[0]}; i++)); do
		local c=${rstr:i:1}

		chattr +$c $wfile || error "Flag [$c] should succeed"
	done

	local attr1=($(lsattr $wfile))
	echo $attr1

	[[ -n ${attr1//-/} ]] || error "lsattr failed: $(lsattr $wfile)"

	stop mds1
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS || error "mds1 start fail"

	wait_recovery_complete $SINGLEMDS || error "MDS recovery not done"

	local attr2=($(lsattr $wfile))
	echo $attr2
	[[ "$attr1" == "$attr2" ]] ||
		error "'$attr1' different with '$attr2'"

}
run_test 162 "File attributes should be persisted after MDS failover"

test_163() {
	remote_mds_nodsh && skip "remote MDS with nodsh"
	(( "$MDS1_VERSION" >= $(version_code 2.16.54) )) ||
		skip "Need MDS version at least 2.16.54 to skip llog holes"

	local mdtidx
	local mdtsvc

	changelog_register || error "changelog_register failed"
	stack_trap changelog_deregister EXIT
	test_mkdir -c 0 $DIR/$tdir || error "mkdir $tdir failed"
	mdtidx=$(($($LFS getdirstripe -i $DIR/$tdir) + 1))
	mdtsvc=$(facet_svc mds$mdtidx)
	echo mds$mdtidx $mdtsvc

	cl_mask=$(do_facet mds$mdtidx $LCTL get_param mdd.$mdtsvc.changelog_mask -n)
	changelog_chmask "ALL"
	stack_trap "do_facet mds$mdtidx \
		$LCTL set_param mdd.$mdtsvc.changelog_mask=\'$cl_mask\' -n" EXIT

	#define OBD_FAIL_MDS_CHANGELOG_FAIL_WRITE			0x18f
	do_facet mds$mdtidx $LCTL set_param fail_loc=0x18f fail_val=30

	# generate some changelog records to create a gap every 31 index
	for (( i = 0; i < 10; i++)); do
		createmany -m $DIR/$tdir/$tfile_$i 40 &
	done

	# Check changelog gap processing without a jump to a next chunk
	changelog_dump | awk -F'[ .]' '{if(prev != "" && $2 - prev > 2) \
			{print"Errot between "prev" and "$2; exit 1}prev=$2}' ||
			error "Found a gap"
}
run_test 163 "changelog check for fail write and processing records"

complete_test $SECONDS
check_and_cleanup_lustre
exit_status
