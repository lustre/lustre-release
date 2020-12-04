#!/bin/bash

set -e

PTLDEBUG=${PTLDEBUG:--1}
MOUNT_2=${MOUNT_2:-"yes"}

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

remote_mds_nodsh && skip "remote MDS with nodsh" && exit 0

ALWAYS_EXCEPT="$REPLAY_DUAL_EXCEPT "
# bug number for skipped test:  LU-2012 LU-8333 LU-7372
ALWAYS_EXCEPT+="                14b     21b     26 "
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[[ "$mds1_FSTYPE" == zfs ]] &&
# bug number for skipped test:        LU-2230
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 21b"

#                                   7  (min)"
[ "$SLOW" = "no" ] && EXCEPT_SLOW="21b "

build_test_filter
check_and_setup_lustre

MOUNTED=$(mounted_lustre_filesystems)
if ! $(echo $MOUNTED' ' | grep -w -q $MOUNT2' '); then
	zconf_mount $HOSTNAME $MOUNT2
	MOUNTED2=yes
fi

assert_DIR
rm -rf $DIR/[df][0-9]*

[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE

# if there is no CLIENT1 defined, some tests can be ran on localhost
CLIENT1=${CLIENT1:-$HOSTNAME}
# if CLIENT2 doesn't exist then use CLIENT1 instead
# All tests should use CLIENT2 with MOUNT2 only therefore it will work if
# $CLIENT2 == CLIENT1
# Exception is the test which need two separate nodes
CLIENT2=${CLIENT2:-$CLIENT1}

# LU-482 Avert LVM and VM inability to flush caches in pre .33 kernels
if [ $LINUX_VERSION_CODE -lt $(version_code 2.6.33) ]; then
	sync
	do_facet $SINGLEMDS "sync; sleep 10; sync; sleep 10; sync"
fi

LU482_FAILED=$(mktemp -u $TMP/$TESTSUITE.lu482.XXXXXX)
test_0a() {
	echo "Check file is LU482_FAILED=$LU482_FAILED"
	touch $MOUNT2/$tfile-A # force sync FLD/SEQ update before barrier
	replay_barrier $SINGLEMDS
#define OBD_FAIL_PTLRPC_FINISH_REPLAY | OBD_FAIL_ONCE
	touch $MOUNT2/$tfile
	createmany -o $MOUNT1/$tfile- 50
	$LCTL set_param fail_loc=0x80000514
	facet_failover $SINGLEMDS
	[ -f "$LU482_FAILED" ] && skip "LU-482 failure" && return 0
	client_up || return 1
	umount -f $MOUNT2
	client_up || return 1
	zconf_mount `hostname` $MOUNT2 || error "mount2 fais"
	unlinkmany $MOUNT1/$tfile- 50 || return 2
	rm $MOUNT2/$tfile || return 3
	rm $MOUNT2/$tfile-A || return 4
}
run_test 0a "expired recovery with lost client"

if [ -f "$LU482_FAILED" ]; then
	log "Found check file $LU482_FAILED, aborting test script"
	rm -vf "$LU482_FAILED"
	complete $SECONDS
	do_nodes $CLIENTS umount -f $MOUNT2 || true
	do_nodes $CLIENTS umount -f $MOUNT || true
	# copied from stopall, but avoid the MDS recovery
    for num in `seq $OSTCOUNT`; do
        stop ost$num -f
        rm -f $TMP/ost${num}active
    done
    if ! combined_mgs_mds ; then
        stop mgs
    fi

	exit_status
fi

test_0b() {
    replay_barrier $SINGLEMDS
    touch $MOUNT2/$tfile
    touch $MOUNT1/$tfile-2
    umount $MOUNT2
    facet_failover $SINGLEMDS
    umount -f $MOUNT1
    zconf_mount `hostname` $MOUNT1 || error "mount1 fais"
    zconf_mount `hostname` $MOUNT2 || error "mount2 fais"
    # it is uncertain if file-2 exists or not, remove it if it does
    checkstat $MOUNT1/$tfile-2 && rm $MOUNT1/$tfile-2
    checkstat $MOUNT2/$tfile && return 2
    return 0
}
run_test 0b "lost client during waiting for next transno"

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
    multiop_bg_pause $MOUNT2/a o_tSc || return  1
    pid=$!
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
    multiop_bg_pause $MOUNT2/a o_c || return 1
    pid1=$!
    multiop_bg_pause $MOUNT1/a o_c || return 1
    pid2=$!
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
    do_facet $SINGLEMDS lctl set_param fail_loc=0x80000119
    fail $SINGLEMDS
    do_facet $SINGLEMDS lctl set_param fail_loc=0

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
    do_facet $SINGLEMDS lctl set_param fail_loc=0x80000119
    fail $SINGLEMDS
    do_facet $SINGLEMDS lctl set_param fail_loc=0

    checkstat $MOUNT1/$tfile-1 && return 1
    checkstat $MOUNT1/$tfile-2 || return 2
    rm $MOUNT1/$tfile-2

    return 0
}
run_test 10 "resending a replayed unlink"

test_11() {
	replay_barrier $SINGLEMDS
	mcreate $DIR1/$tfile-1
	mcreate $DIR2/$tfile-2
	mcreate $DIR1/$tfile-3
	mcreate $DIR2/$tfile-4
	mcreate $DIR1/$tfile-5
	# drop all reint replies for a while
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x0119
	# note that with this fail_loc set, facet_failover df will fail
	facet_failover $SINGLEMDS

	local clients=${CLIENTS:-$HOSTNAME}
	wait_clients_import_state "$clients" $SINGLEMDS FULL

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	rm $DIR1/$tfile-[1-5] || return 1

	return 0
}
run_test 11 "both clients timeout during replay"

test_12() {
    replay_barrier $SINGLEMDS

    multiop_bg_pause $DIR/$tfile mo_c || return 1
    MULTIPID=$!

#define OBD_FAIL_LDLM_ENQUEUE_NET			0x302
    do_facet $SINGLEMDS lctl set_param fail_loc=0x80000302
    facet_failover $SINGLEMDS
    do_facet $SINGLEMDS lctl set_param fail_loc=0
    clients_up || return 1

    ls $DIR/$tfile
    kill -USR1 $MULTIPID || return 3
    wait $MULTIPID || return 4
    $CHECKSTAT -t file $DIR/$tfile || return 2
    rm $DIR/$tfile

    return 0
}
run_test 12 "open resend timeout"

test_13() {
    multiop_bg_pause $DIR/$tfile mo_c || return 1
    MULTIPID=$!

    replay_barrier $SINGLEMDS

    kill -USR1 $MULTIPID || return 3
    wait $MULTIPID || return 4

    # drop close
    do_facet $SINGLEMDS lctl set_param fail_loc=0x80000115
    facet_failover $SINGLEMDS
    do_facet $SINGLEMDS lctl set_param fail_loc=0
    clients_up || return 1

    ls $DIR/$tfile
    $CHECKSTAT -t file $DIR/$tfile || return 2
    rm $DIR/$tfile

    return 0
}
run_test 13 "close resend timeout"

# test 14a removed after 18143 because it shouldn't fail anymore and do the same
# as test_15a

test_14b() {
	wait_mds_ost_sync
	wait_delete_completed

	local beforeused=$(df -P $DIR | tail -1 | awk '{ print $3 }')

	mkdir -p $MOUNT1/$tdir
	$LFS setstripe -i 0 $MOUNT1/$tdir
	replay_barrier $SINGLEMDS
	createmany -o $MOUNT1/$tdir/$tfile- 5

	$LFS setstripe -i 0 $MOUNT2/$tfile-2
	dd if=/dev/zero of=$MOUNT2/$tfile-2 bs=1M count=5
	createmany -o $MOUNT1/$tdir/$tfile-3- 5
	umount $MOUNT2

	fail $SINGLEMDS
	wait_recovery_complete $SINGLEMDS || error "MDS recovery not done"

	# first set of files should have been replayed
	unlinkmany $MOUNT1/$tdir/$tfile- 5 || error "first unlinks failed"
	unlinkmany $MOUNT1/$tdir/$tfile-3- 5 || error "second unlinks failed"

	zconf_mount $HOSTNAME $MOUNT2 || error "mount $MOUNT2 failed"
	[ -f $MOUNT2/$tfile-2 ] && error "$MOUNT2/$tfile-2 exists!"

	wait_mds_ost_sync || error "wait_mds_ost_sync failed"
	wait_delete_completed || error "wait_delete_complete failed"

	local afterused=$(df -P $DIR | tail -1 | awk '{ print $3 }')
	log "before $beforeused, after $afterused"
	# leave some margin for some files/dirs to be modified (OI, llog, etc)
	[ $afterused -le $((beforeused + $(fs_log_size))) ] ||
		error "after $afterused > before $beforeused"
}
run_test 14b "delete ost orphans if gap occured in objids due to VBR"

test_15a() { # was test_15
    replay_barrier $SINGLEMDS
    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1
    umount $MOUNT2

    fail $SINGLEMDS

    unlinkmany $MOUNT1/$tfile- 25 || return 2
    [ -e $MOUNT1/$tfile-2-0 ] && error "$tfile-2-0 exists"

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    return 0
}
run_test 15a "timeout waiting for lost client during replay, 1 client completes"

test_15c() {
    replay_barrier $SINGLEMDS
    for ((i = 0; i < 2000; i++)); do
        echo "data" > "$MOUNT2/${tfile}-$i" || error "create ${tfile}-$i failed"
    done
    umount $MOUNT2

    fail $SINGLEMDS

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
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
    fail $SINGLEMDS

    unlinkmany $MOUNT1/$tfile- 25 || return 2

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    return 0

}
run_test 16 "fail MDS during recovery (3571)"

test_17() {
    remote_ost_nodsh && skip "remote OST with nodsh" && return 0

    createmany -o $MOUNT1/$tfile- 25
    createmany -o $MOUNT2/$tfile-2- 1

    # Make sure the disconnect is lost
    replay_barrier ost1
    umount $MOUNT2

    facet_failover ost1
    sleep $TIMEOUT
    fail ost1

    unlinkmany $MOUNT1/$tfile- 25 || return 2

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"
    return 0

}
run_test 17 "fail OST during recovery (3571)"

# cleanup with blocked enqueue fails until timer elapses (MDS busy), wait for it
export NOW=0

test_18() { # bug 3822 - evicting client with enqueued lock
	#set -vx
	local DLMTRACE=$(do_facet $SINGLEMDS lctl get_param debug)
	do_facet $SINGLEMDS lctl set_param debug=+dlmtrace
	mkdir -p $MOUNT1/$tdir || error "mkdir $MOUNT1/$tdir failed"
	touch $MOUNT1/$tdir/${tfile}0 || error "touch file failed"
	statmany -s $MOUNT1/$tdir/$tfile 1 500 &
	OPENPID=$!
	NOW=$SECONDS
	#define OBD_FAIL_LDLM_ENQUEUE_BLOCKED    0x30b
	do_facet $SINGLEMDS lctl set_param fail_loc=0x8000030b  # hold enqueue
	sleep 1
	#define OBD_FAIL_LDLM_BL_CALLBACK_NET			0x305
	do_facet client lctl set_param ldlm.namespaces.*.early_lock_cancel=0
	do_facet client lctl set_param fail_loc=0x80000305  # drop cb, evict
	cancel_lru_locks mdc
	sleep 0.1 # wait to ensure first client is one that will be evicted
	openfile -f O_RDONLY $MOUNT2/$tdir/$tfile
	wait $OPENPID
	do_facet client lctl set_param ldlm.namespaces.*.early_lock_cancel=1
	do_facet $SINGLEMDS lctl debug_kernel |
		grep "not entering recovery" && error "client not evicted"
	do_facet client "lctl set_param fail_loc=0"
	do_facet $SINGLEMDS "lctl set_param fail_loc=0"
}
run_test 18 "ldlm_handle_enqueue succeeds on evicted export (3822)"

test_19() { # Bug 10991 - resend of open request does not fail assertion.
    replay_barrier $SINGLEMDS
    drop_mdt_ldlm_reply "createmany -o $DIR/$tfile 1" || return 1
    fail $SINGLEMDS
    checkstat $DIR2/${tfile}0 || return 2
    rm $DIR/${tfile}0 || return 3

    return 0
}
run_test 19 "resend of open request"

test_20() { #16389
	local before=$SECONDS
	replay_barrier $SINGLEMDS
	touch $DIR1/$tfile.a
	touch $DIR2/$tfile.b
	umount $DIR2
	fail $SINGLEMDS
	rm $DIR1/$tfile.a
	zconf_mount $HOSTNAME $DIR2 || error "mount $DIR2 fail"
	local tier1=$((SECONDS - before))

	before=$SECONDS
	replay_barrier $SINGLEMDS
	touch $DIR1/$tfile.a
	touch $DIR2/$tfile.b
	umount $DIR2
	fail $SINGLEMDS
	rm $DIR1/$tfile.a
	zconf_mount $HOSTNAME $DIR2 || error "mount $DIR2 fail"
	local tier2=$((SECONDS - before))

	# timeout is more than 1.5x original timeout
	((tier2 < tier1 * 6 / 4)) ||
		error "recovery time $tier2 >= 1.5x original time $tier1"
}
run_test 20 "recovery time is not increasing"

# commit on sharing tests
test_21a() {
    local param_file=$TMP/$tfile-params

	save_lustre_params $SINGLEMDS "mdt.*.commit_on_sharing" > $param_file
    do_facet $SINGLEMDS lctl set_param mdt.*.commit_on_sharing=1
    touch  $MOUNT1/$tfile-1
    mv  $MOUNT2/$tfile-1 $MOUNT2/$tfile-2
    mv  $MOUNT1/$tfile-2 $MOUNT1/$tfile-3
    replay_barrier_nosync $SINGLEMDS
    umount $MOUNT2

    facet_failover $SINGLEMDS

    # all renames are replayed
    unlink  $MOUNT1/$tfile-3 || return 2

    zconf_mount `hostname` $MOUNT2 || error "mount $MOUNT2 fail"

    do_facet $SINGLEMDS lctl set_param mdt.*.commit_on_sharing=0
    rm -rf $MOUNT1/$tfile-*
    restore_lustre_params < $param_file
    rm -f $param_file
    return 0
}
run_test 21a "commit on sharing"

test_21b_sub () {
	local mds=$1
	do_node $CLIENT1 rm -f $MOUNT1/$tfile-*

	do_facet $mds sync
	do_node $CLIENT1 touch $MOUNT1/$tfile-1
	do_node $CLIENT2 mv $MOUNT1/$tfile-1 $MOUNT1/$tfile-2
	do_node $CLIENT1 mv $MOUNT1/$tfile-2 $MOUNT1/$tfile-3

	replay_barrier_nosync $mds
	shutdown_client $CLIENT2 $MOUNT1

	facet_failover $mds

	# were renames replayed?
	local rc=0
	echo UNLINK $MOUNT1/$tfile-3
	do_node $CLIENT1 unlink  $MOUNT1/$tfile-3 ||
		{ echo "unlink $tfile-3 fail!" && rc=1; }

	boot_node $CLIENT2
	zconf_mount_clients $CLIENT2 $MOUNT1 ||
		error "mount $CLIENT2 $MOUNT1 fail"

	return $rc
}

test_21b() {
	[ -z "$CLIENTS" ] && skip "Need two or more clients" && return
	[ $CLIENTCOUNT -lt 2 ] &&
		{ skip "Need 2+ clients, have $CLIENTCOUNT" && return; }

	if [ "$FAILURE_MODE" = "HARD" ] && mixed_mdt_devs; then
		skip "Several MDTs on one MDS with FAILURE_MODE=$FAILURE_MODE"
		return 0
	fi

	zconf_umount_clients $CLIENTS $MOUNT2
	zconf_mount_clients $CLIENTS $MOUNT1

	local param_file=$TMP/$tfile-params

	local mdtidx=$($LFS getstripe -m $MOUNT1)
	local facet=mds$((mdtidx + 1))

	save_lustre_params $facet "mdt.*.commit_on_sharing" > $param_file

	# COS enabled
	local COS=1
	do_facet $facet lctl set_param mdt.*.commit_on_sharing=$COS

	test_21b_sub $facet || error "Not all renames are replayed. COS=$COS"

	# there is still a window when transactions may be written to disk
	# before the mds device is set R/O. To avoid such a rare test failure,
	# the check is repeated several times.
	COS=0
	local n_attempts=1
	while true; do
		# COS disabled (should fail)
		do_facet $facet lctl set_param mdt.*.commit_on_sharing=$COS

		test_21b_sub $facet || break
		n_attempts=$((n_attempts + 1))
		[ $n_attempts -gt 3 ] &&
			error "can't check if COS works: rename replied w/o COS"
	done
	zconf_mount_clients $CLIENTS $MOUNT2
	restore_lustre_params < $param_file
	rm -f $param_file
	return 0
}
run_test 21b "commit on sharing, two clients"

checkstat_22() {
	checkstat $MOUNT1/$remote_dir || return 1
	checkstat $MOUNT1/$remote_dir/dir || return 2
	checkstat $MOUNT1/$remote_dir/$tfile-1 || return 3
	checkstat $MOUNT1/$remote_dir/dir/$tfile-1 || return 4
	return 0
}

create_remote_dir_files_22() {
	do_node $CLIENT2 mkdir ${MOUNT2}/$remote_dir/dir || return 1
	do_node $CLIENT1 createmany -o $MOUNT1/$remote_dir/dir/$tfile- 2 ||
							    return 2
	do_node $CLIENT2 createmany -o $MOUNT2/$remote_dir/$tfile- 2 ||
							    return 3
	return 0
}

test_22a () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	([ $FAILURE_MODE == "HARD" ] &&
		[ "$(facet_host mds1)" == "$(facet_host mds2)" ]) &&
		skip "MDTs needs to be on diff hosts for HARD fail mode" &&
		return 0

	local MDTIDX=1
	local remote_dir=${tdir}/remote_dir

	do_node $CLIENT1 mkdir -p $MOUNT1/${tdir}

	# OBD_FAIL_MDS_REINT_NET_REP       0x119
	do_facet mds$((MDTIDX + 1)) lctl set_param fail_loc=0x119
	do_node $CLIENT1 $LFS mkdir -i $MDTIDX $MOUNT1/$remote_dir &
	CLIENT_PID=$!
	sleep 1

	fail mds$((MDTIDX + 1))
	wait $CLIENT_PID || error "lfs mkdir failed"

	replay_barrier mds$MDTIDX
	create_remote_dir_files_22 || error "Remote creation failed $?"
	fail mds$MDTIDX

	checkstat_22 || error "check stat failed $?"

	rm -rf $MOUNT1/$tdir || error "rmdir remote_dir failed"
	return 0
}
run_test 22a "c1 lfs mkdir -i 1 dir1, M1 drop reply & fail, c2 mkdir dir1/dir"

test_22b () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	local MDTIDX=1
	local remote_dir=$tdir/remote_dir

	# OBD_FAIL_MDS_REINT_NET_REP       0x119
	do_node $CLIENT1 mkdir -p $MOUNT1/${tdir}

	do_facet mds$((MDTIDX + 1)) lctl set_param fail_loc=0x119
	do_node $CLIENT1 $LFS mkdir -i $MDTIDX $MOUNT1/$remote_dir &
	CLIENT_PID=$!
	sleep 1

	fail mds${MDTIDX},mds$((MDTIDX + 1))
	wait $CLIENT_PID || error "lfs mkdir failed"

	replay_barrier mds$MDTIDX
	create_remote_dir_files_22 || error "Remote creation failed $?"
	fail mds${MDTIDX}

	checkstat_22 || error "check stat failed $?"

	rm -rf $MOUNT1/$tdir || error "rmdir remote_dir failed"
	return 0
}
run_test 22b "c1 lfs mkdir -i 1 d1, M1 drop reply & fail M0/M1, c2 mkdir d1/dir"

test_22c () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	([ $FAILURE_MODE == "HARD" ] &&
		[ "$(facet_host mds1)" == "$(facet_host mds2)" ]) &&
		skip "MDTs needs to be on diff hosts for HARD fail mode" &&
		return 0
	local MDTIDX=1
	local remote_dir=${tdir}/remote_dir

	do_node $CLIENT1 mkdir -p $MOUNT1/${tdir}

	# OBD_FAIL_OUT_UPDATE_NET_REP    0x1701
	do_facet mds$MDTIDX lctl set_param fail_loc=0x1701
	do_node $CLIENT1 $LFS mkdir -i $MDTIDX $MOUNT1/$remote_dir &
	CLIENT_PID=$!
	sleep 1
	do_facet mds$MDTIDX lctl set_param fail_loc=0

	fail mds$MDTIDX
	wait $CLIENT_PID || error "lfs mkdir failed"

	replay_barrier mds$MDTIDX
	create_remote_dir_files_22 || error "Remote creation failed $?"
	fail mds$MDTIDX

	checkstat_22 || error "check stat failed $?"

	rm -rf $MOUNT1/$tdir || error "rmdir remote_dir failed"
	return 0
}
run_test 22c "c1 lfs mkdir -i 1 d1, M1 drop update & fail M1, c2 mkdir d1/dir"

test_22d () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	local MDTIDX=1
	local remote_dir=${tdir}/remote_dir

	do_node $CLIENT1 mkdir -p $MOUNT1/${tdir}

	# OBD_FAIL_OUT_UPDATE_NET_REP    0x1701
	do_facet mds$MDTIDX lctl set_param fail_loc=0x1701
	do_node $CLIENT1 $LFS mkdir -i $MDTIDX $MOUNT1/$remote_dir &
	CLIENT_PID=$!
	sleep 1
	do_facet mds$MDTIDX lctl set_param fail_loc=0

	fail mds${MDTIDX},mds$((MDTIDX + 1))
	wait $CLIENT_PID || error "lfs mkdir failed"

	replay_barrier mds$MDTIDX
	create_remote_dir_files_22 || error "Remote creation failed $?"
	fail mds$MDTIDX

	checkstat_22 || error "check stat failed $?"

	rm -rf $MOUNT1/$tdir || error "rmdir remote_dir failed"
	return 0
}
run_test 22d "c1 lfs mkdir -i 1 d1, M1 drop update & fail M0/M1,c2 mkdir d1/dir"

checkstat_23() {
	checkstat $MOUNT1/$remote_dir || return 1
	checkstat $MOUNT1/$remote_dir/$tfile-1 || return 2
	return 0
}

create_remote_dir_files_23() {
	do_node $CLIENT2 mkdir ${MOUNT2}/$remote_dir || return 1
	do_node $CLIENT2 createmany -o $MOUNT2/$remote_dir/$tfile- 2 || return 2
	return 0
}

test_23a () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	([ $FAILURE_MODE == "HARD" ] &&
		[ "$(facet_host mds1)" == "$(facet_host mds2)" ]) &&
		skip "MDTs needs to be on diff hosts for HARD fail mode" &&
		return 0
	local MDTIDX=1
	local remote_dir=$tdir/remote_dir

	do_node $CLIENT1 mkdir -p $MOUNT1/${tdir}
	do_node $CLIENT1 $LFS mkdir -i $MDTIDX $MOUNT1/$remote_dir ||
			error "lfs mkdir failed"
	# OBD_FAIL_MDS_REINT_NET_REP       0x119
	do_facet mds$((MDTIDX + 1)) lctl set_param fail_loc=0x119
	do_node $CLIENT1 rmdir $MOUNT1/$remote_dir &
	local CLIENT_PID=$!
	sleep 1
	do_facet mds$((MDTIDX + 1)) lctl set_param fail_loc=0

	fail mds$((MDTIDX + 1))
	wait $CLIENT_PID || error "rmdir remote dir failed"

	replay_barrier mds${MDTIDX}
	create_remote_dir_files_23 || error "Remote creation failed $?"
	fail mds${MDTIDX}

	checkstat_23 || error "check stat failed $?"

	rm -rf $MOUNT1/$tdir || error "rmdir remote_dir failed"
	return 0
}
run_test 23a "c1 rmdir d1, M1 drop reply and fail, client2 mkdir d1"

test_23b () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	local MDTIDX=1
	local remote_dir=$tdir/remote_dir

	do_node $CLIENT1 mkdir -p $MOUNT1/${tdir}
	do_node $CLIENT1 $LFS mkdir -i $MDTIDX $MOUNT1/$remote_dir ||
			error "lfs mkdir failed"

	# OBD_FAIL_MDS_REINT_NET_REP       0x119
	do_facet mds$((MDTIDX + 1)) lctl set_param fail_loc=0x119
	do_node $CLIENT1 rmdir $MOUNT1/$remote_dir &
	local CLIENT_PID=$!
	sleep 1
	do_facet mds$((MDTIDX + 1)) lctl set_param fail_loc=0

	fail mds${MDTIDX},mds$((MDTIDX + 1))
	wait $CLIENT_PID || error "rmdir remote dir failed"

	replay_barrier mds${MDTIDX}
	create_remote_dir_files_23 || error "Remote creation failed $?"
	fail mds${MDTIDX}

	checkstat_23 || error "check stat failed $?"

	rm -rf $MOUNT1/$tdir || error "rmdir remote_dir failed"
	return 0
}
run_test 23b "c1 rmdir d1, M1 drop reply and fail M0/M1, c2 mkdir d1"

test_23c () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0

	([ $FAILURE_MODE == "HARD" ] &&
		[ "$(facet_host mds1)" == "$(facet_host mds2)" ]) &&
		skip "MDTs needs to be on diff hosts for HARD fail mode" &&
		return 0
	local MDTIDX=1
	local remote_dir=$tdir/remote_dir

	do_node $CLIENT1 mkdir -p $MOUNT1/${tdir}
	do_node $CLIENT1 $LFS mkdir -i $MDTIDX $MOUNT1/$remote_dir ||
			error "lfs mkdir failed"

	# OBD_FAIL_OUT_UPDATE_NET_REP    0x1701
	do_facet mds${MDTIDX} lctl set_param fail_loc=0x1701
	do_node $CLIENT1 rmdir $MOUNT1/$remote_dir &
	CLIENT_PID=$!
	sleep 1
	do_facet mds${MDTIDX} lctl set_param fail_loc=0

	fail mds${MDTIDX}
	wait $CLIENT_PID || error "rmdir remote dir failed"

	replay_barrier mds${MDTIDX}
	create_remote_dir_files_23 || error "Remote creation failed $?"
	fail mds${MDTIDX}

	checkstat_23 || error "check stat failed $?"

	rm -rf $MOUNT1/$tdir || return 6
	return 0
}
run_test 23c "c1 rmdir d1, M0 drop update reply and fail M0, c2 mkdir d1"

test_23d () {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	local MDTIDX=1
	local remote_dir=$tdir/remote_dir

	do_node $CLIENT1 mkdir -p $MOUNT1/${tdir}
	do_node $CLIENT1 $LFS mkdir -i $MDTIDX $MOUNT1/$remote_dir ||
			error "lfs mkdir failed"

	# OBD_FAIL_UPDATE_OBJ_NET    0x1701
	do_facet mds${MDTIDX} lctl set_param fail_loc=0x1701
	do_node $CLIENT1 rmdir $MOUNT1/$remote_dir &
	CLIENT_PID=$!
	sleep 1
	do_facet mds${MDTIDX} lctl set_param fail_loc=0

	fail mds${MDTIDX},mds$((MDTIDX + 1))
	wait $CLIENT_PID || error "rmdir remote dir failed"

	replay_barrier mds${MDTIDX}
	create_remote_dir_files_23 || error "Remote creation failed $?"
	fail mds${MDTIDX}

	checkstat_23 || error "check stat failed $?"

	rm -rf $MOUNT1/$tdir || return 6
	return 0
}
run_test 23d "c1 rmdir d1, M0 drop update reply and fail M0/M1, c2 mkdir d1"

test_24 () {
	[[ "$MDS1_VERSION" -gt $(version_code 2.5.2) ]] ||
		skip "Need MDS version newer than 2.5.2"

	touch $MOUNT/$tfile
	stat $MOUNT/$tfile >&/dev/null
# OBD_FAIL_MDS_REINT_NET_REP
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x119
	$TRUNCATE $MOUNT/$tfile 100 &
	PID=$!
	sleep 1
	do_facet $SINGLEMDS lctl set_param fail_loc=0
	# sync to release rep-ack lock quickly
	do_nodes $(comma_list $(mdts_nodes)) \
	    "lctl set_param -n osd*.*MDT*.force_sync 1"
	rm $MOUNT2/$tfile
	wait
}
run_test 24 "reconstruct on non-existing object"

# end commit on sharing tests 

test_25() {
	cancel_lru_locks osc

	$LFS setstripe -i 0 -c 1 $DIR/$tfile

	# get lock for the 1st client
	dd if=/dev/zero of=$DIR/$tfile count=1 >/dev/null ||
		error "failed to write data"

	# get waiting locks for the 2nd client
	drop_ldlm_cancel "multiop $DIR2/$tfile Ow512" &
	sleep 1

	# failover, replay and resend replayed waiting locks
	if [ "$OST1_VERSION" -ge $(version_code 2.6.90) ]; then
		#define OBD_FAIL_LDLM_SRV_CP_AST      0x325
		do_facet ost1 lctl set_param fail_loc=0x80000325
	else
		#define OBD_FAIL_OST_LDLM_REPLY_NET	0x213
		do_facet ost1 lctl set_param fail_loc=0x80000213
	fi

	fail ost1

	# multiop does not finish because CP AST is skipped;
	# it is ok to kill it in the test, because CP AST is already re-sent
	# and it does not hung forever in real life
	killall multiop
	wait
}
run_test 25 "replay|resend"

cleanup_26() {
	trap 0
	kill -9 $tar_26_pid
	kill -9 $dbench_26_pid
	killall -9 dbench
}

test_26() {
	local clients=${CLIENTS:-$HOSTNAME}

	zconf_mount_clients $clients $MOUNT

	local duration=600
	[ "$SLOW" = "no" ] && duration=200
	# set duration to 900 because it takes some time to boot node
	[ "$FAILURE_MODE" = HARD ] && duration=900

	local start_ts=$SECONDS
	local rc=0

	trap cleanup_26	EXIT
	(
		local tar_dir=$DIR/$tdir/run_tar
		while true; do
			test_mkdir -p -c$MDSCOUNT $tar_dir || break
			if [ $MDSCOUNT -ge 2 ]; then
				$LFS setdirstripe -D -c$MDSCOUNT $tar_dir ||
					error "set default dirstripe failed"
			fi
			cd $tar_dir || break
			tar cf - /etc | tar xf - || error "tar failed"
			cd $DIR/$tdir || break
			rm -rf $tar_dir || break
		done
	)&
	tar_26_pid=$!
	echo "Started tar $tar_26_pid"

	(
		local dbench_dir=$DIR2/$tdir/run_dbench
		while true; do
			test_mkdir -p -c$MDSCOUNT $dbench_dir || break
			if [ $MDSCOUNT -ge 2 ]; then
				$LFS setdirstripe -D -c$MDSCOUNT $dbench_dir ||
					error "set default dirstripe failed"
			fi
			cd $dbench_dir || break
			rundbench 1 -D $dbench_dir -t 100 &>/dev/null || break
			cd $DIR/$tdir || break
			rm -rf $dbench_dir || break
		done
	)&
	dbench_26_pid=$!
	echo "Started dbench $dbench_26_pid"

	local num_failovers=0
	local fail_index=1
	while [ $((SECONDS - start_ts)) -lt $duration ]; do
		kill -0 $tar_26_pid || error "tar $tar_26_pid missing"
		kill -0 $dbench_26_pid || error "dbench $dbench_26_pid missing"
		sleep 2
		replay_barrier mds$fail_index
		sleep 2 # give clients a time to do operations
		# Increment the number of failovers
		num_failovers=$((num_failovers + 1))
		log "$TESTNAME fail mds$fail_index $num_failovers times"
		fail mds$fail_index
		if [ $fail_index -ge $MDSCOUNT ]; then
			fail_index=1
		else
			fail_index=$((fail_index + 1))
		fi
	done
	# stop the client loads
	kill -0 $tar_26_pid || error "tar $tar_26_pid stopped"
	kill -0 $dbench_26_pid || error "dbench $dbench_26_pid stopped"
	cleanup_26 || true
}
run_test 26 "dbench and tar with mds failover"

test_28() {
	$LFS setstripe -i 0 -c 1 $DIR2/$tfile
	dd if=/dev/zero of=$DIR2/$tfile bs=4096 count=1

	#define OBD_FAIL_LDLM_SRV_BL_AST	 0x324
	do_facet ost1 $LCTL set_param fail_loc=0x80000324

	dd if=/dev/zero of=$DIR/$tfile bs=4096 count=1 &
	local pid=$!
	sleep 2

	#define OBD_FAIL_LDLM_GRANT_CHECK        0x32a
	do_facet ost1 $LCTL set_param fail_loc=0x32a

	fail ost1

	sleep 2
	cancel_lru_locks OST0000-osc
	wait $pid || error "dd failed"
}
run_test 28 "lock replay should be ordered: waiting after granted"

test_29() {
	local dir0=$DIR/$tdir/d0
	local dir1=$DIR/$tdir/d1

	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return 0
	[ $CLIENTCOUNT -lt 2 ] && skip "needs >= 2 clients" && return 0
	[ "$CLIENT1" == "$CLIENT2" ] &&
		skip "clients must be on different nodes" && return 0

	mkdir -p $DIR/$tdir
	$LFS mkdir -i0 $dir0
	$LFS mkdir -i1 $dir1
	sync

	replay_barrier mds2
	# create a remote dir, drop reply
	#define OBD_FAIL_PTLRPC_ROUND_XID 0x530
	$LCTL set_param fail_loc=0x530 fail_val=36
	#define OBD_FAIL_MDS_REINT_MULTI_NET_REP 0x15a
	do_facet mds2 $LCTL set_param fail_loc=0x8000015a
	echo make remote dir d0 for $dir0
	$LFS mkdir -i1 -c1 $dir0/d3 &
	sleep 1

	echo make local dir d1 for $dir1
	do_node $CLIENT2 $LCTL set_param fail_loc=0x530 fail_val=36
	do_node $CLIENT2 mkdir $dir1/d4

	fail mds2
}
run_test 29 "replay vs update with the same xid"

test_30() {
	$LFS setstripe -E 1m -L mdt -E -1 $DIR/$tfile
	#first write to have no problems with grants
	dd if=/dev/zero of=$DIR/$tfile bs=4k count=10 ||
		error "dd on client failed"
	dd if=/dev/zero of=$DIR/$tfile bs=4k count=10 seek=10 ||
		error "dd on client failed"

	#define OBD_FAIL_LDLM_REPLAY_PAUSE	 0x32e
	lctl set_param fail_loc=0x32e fail_val=4
	dd of=/dev/null if=$DIR2/$tfile &
	local pid=$!
	sleep 1

	fail $SINGLEMDS

	wait $pid || error "dd on client failed"
}
run_test 30 "layout lock replay is not blocked on IO"

complete $SECONDS
SLEEP=$((SECONDS - $NOW))
[ $SLEEP -lt $TIMEOUT ] && sleep $SLEEP
[ "$MOUNTED2" = yes ] && zconf_umount $HOSTNAME $MOUNT2 || true
check_and_cleanup_lustre
exit_status
