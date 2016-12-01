#!/bin/bash

set -e

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

# While we do not use OSTCOUNT=1 setup anymore,
# ost1failover_HOST is used
#ostfailover_HOST=${ostfailover_HOST:-$ost_HOST}
#failover= must be defined in OST_MKFS_OPTIONS if ostfailover_HOST != ost_HOST

require_dsh_ost || exit 0

# bug number for skipped test:
ALWAYS_EXCEPT="$REPLAY_OST_SINGLE_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# bug number for SLOW test:
#                                  40  (min)"
[ "$SLOW" = "no" ] && EXCEPT_SLOW="5"

if [ $(facet_fstype $SINGLEMDS) = "zfs" ]; then
# bug number for skipped test:      LU-2285
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 3"
# bug number for slowed tests:                          LU-2887
	#                                               32  12.5  (min)"
	[ "$SLOW" = "no" ] && EXCEPT_SLOW="$EXCEPT_SLOW 8a  8b"
fi

build_test_filter

check_and_setup_lustre
assert_DIR
rm -rf $DIR/[df][0-9]*

TDIR=$DIR/d0.${TESTSUITE}
mkdir -p $TDIR
$SETSTRIPE $TDIR -i 0 -c 1
$GETSTRIPE $TDIR

test_0a() {
	zconf_umount $(hostname) $MOUNT -f
	# needs to run during initial client->OST connection
	#define OBD_FAIL_OST_ALL_REPLY_NET       0x211
	do_facet ost1 "lctl set_param fail_loc=0x80000211"
	zconf_mount $(hostname) $MOUNT && $LFS df $MOUNT || error "mount fail"
}
run_test 0a "target handle mismatch (bug 5317)"

test_0b() {
	fail ost1
	cp /etc/profile  $TDIR/$tfile
	sync
	diff /etc/profile $TDIR/$tfile
	rm -f $TDIR/$tfile
}
run_test 0b "empty replay"

test_1() {
	date > $TDIR/$tfile || error "error creating $TDIR/$tfile"
	fail ost1
	$CHECKSTAT -t file $TDIR/$tfile || error "check for file failed"
	rm -f $TDIR/$tfile
}
run_test 1 "touch"

test_2() {
	for i in $(seq 10); do
		echo "tag-$i" > $TDIR/$tfile-$i ||
			error "create $TDIR/$tfile-$i failed"
	done
	fail ost1
	for i in $(seq 10); do
		grep -q "tag-$i" $TDIR/$tfile-$i ||
			error "grep $TDIR/$tfile-$i failed"
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
	wait $ddpid || error "wait for dd failed"
	cmp $verify $TDIR/$tfile || error "compare $verify $TDIR/$tfile failed"
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
	wait $cmppid || error "wait on cmp failed"
	rm -f $verify $TDIR/$tfile
}
run_test 4 "Fail OST during read, with verification"

iozone_bg () {
    local args=$@

    local tmppipe=$TMP/${TESTSUITE}.${TESTNAME}.pipe
    mkfifo $tmppipe

    echo "+ iozone $args"
    iozone $args > $tmppipe &

    local pid=$!

    echo "tmppipe=$tmppipe"
    echo iozone pid=$pid

    # iozone exit code is 0 even if iozone is not completed
    # need to check iozone output  on "complete"
    local iozonelog=$TMP/${TESTSUITE}.iozone.log
    rm -f $iozonelog
    cat $tmppipe | while read line ; do
        echo "$line"
        echo "$line" >>$iozonelog
    done;

    local rc=0
    wait $pid
    rc=$?
    if ! $(tail -1 $iozonelog | grep -q complete); then
        echo iozone failed!
        rc=1
    fi
    rm -f $tmppipe
    rm -f $iozonelog
    return $rc
}

test_5() {
	if [ -z "$(which iozone 2> /dev/null)" ]; then
		skip_env "iozone missing"
		return 0
	fi

	# striping is -c 1, get min of available
	local minavail=$(lctl get_param -n osc.*[oO][sS][cC][-_]*.kbytesavail |
		sort -n | head -n1)
	local size=$(( minavail * 3/4 ))
	local GB=1048576  # 1048576KB == 1GB

	if (( size > GB )); then
		size=$GB
	fi
	local iozone_opts="-i 0 -i 1 -i 2 -+d -r 4 -s $size -f $TDIR/$tfile"

	iozone_bg $iozone_opts &
	local pid=$!

	echo iozone bg pid=$pid

	sleep 8
	fail ost1
	local rc=0
	wait $pid || error "wait on iozone failed"
	rc=$?
	log "iozone rc=$rc"
	rm -f $TDIR/$tfile
	wait_delete_completed_mds
	[ $rc -eq 0 ] || error "iozone failed"
	return $rc
}
run_test 5 "Fail OST during iozone"

kbytesfree() {
   calc_osc_kbytes kbytesfree
}

test_6() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return 0

	local f=$TDIR/$tfile
	sync && sleep 5 && sync  # wait for delete thread

	# wait till space is returned, following
	# (( $before > $after_dd)) test counting on that
	wait_mds_ost_sync || error "first wait_mds_ost_sync failed"
	wait_destroy_complete || error "first wait_destroy_complete failed"

	local before=$(kbytesfree)
	dd if=/dev/urandom bs=4096 count=1280 of=$f || error "dd failed"
	$GETSTRIPE $f || error "$GETSTRIPE $f failed"
	local stripe_index=$(lfs getstripe -i $f)

	sync
	sleep 2 # ensure we have a fresh statfs
	sync

	#define OBD_FAIL_MDS_REINT_NET_REP       0x119
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x80000119"

	# retry till statfs returns useful results
	local after_dd=$(kbytesfree)
	local i=0
	while (( $before <= $after_dd && $i < 20 )); do
		sync
		sleep 1
		let ++i
		after_dd=$(kbytesfree)
	done

	log "before: $before after_dd: $after_dd took $i seconds"
	(( $before > $after_dd )) ||
		error "space grew after dd: before:$before after_dd:$after_dd"
	rm -f $f
	fail ost$((stripe_index + 1))
	wait_recovery_complete ost$((stripe_index + 1)) ||
		error "OST$((stripe_index + 1)) recovery not completed"
	$CHECKSTAT -t file $f && return 2 || true
	sync
	# let the delete happen
	wait_mds_ost_sync || error "second wait_mds_ost_sync failed"
	wait_delete_completed || error "second wait_delete_completed failed"
	local after=$(kbytesfree)
	log "before: $before after: $after"
	(( $before <= $after + $(fs_log_size) )) ||
		error "$before > $after + logsize $(fs_log_size)"
}
run_test 6 "Fail OST before obd_destroy"

test_7() {
	local f=$TDIR/$tfile
	sync && sleep 5 && sync	# wait for delete thread

	# wait till space is returned, following
	# (( $before > $after_dd)) test counting on that
	wait_mds_ost_sync || error "wait_mds_ost_sync failed"
	wait_destroy_complete || error "wait_destroy_complete failed"

	local before=$(kbytesfree)
	dd if=/dev/urandom bs=4096 count=1280 of=$f ||
		error "dd to file failed: $?"

	sync
	local after_dd=$(kbytesfree)
	local i=0
	while (( $before <= $after_dd && $i < 10 )); do
		sync
		sleep 1
		let ++i
		after_dd=$(kbytesfree)
	done

	log "before: $before after_dd: $after_dd took $i seconds"
	(( $before > $after_dd )) ||
		error "space grew after dd: before:$before after_dd:$after_dd"
	replay_barrier ost1
	rm -f $f
	fail ost1
	wait_recovery_complete ost1 || error "OST recovery not done"
	$CHECKSTAT -t file $f && return 2 || true
	sync
	# let the delete happen
	wait_mds_ost_sync || error "wait_mds_ost_sync failed"
	wait_delete_completed || error "wait_delete_completed failed"
	local after=$(kbytesfree)
	log "before: $before after: $after"
	(( $before <= $after + $(fs_log_size) )) ||
		 error "$before > $after + logsize $(fs_log_size)"
}
run_test 7 "Fail OST before obd_destroy"

test_8a() {
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.3.0) ]] ||
		{ skip "Need MDS version at least 2.3.0"; return; }
	verify=$ROOT/tmp/verify-$$
	dd if=/dev/urandom of=$verify bs=4096 count=1280 ||
		error "Create verify file failed"
	#define OBD_FAIL_OST_DQACQ_NET 0x230
	do_facet ost1 "lctl set_param fail_loc=0x230"
	dd if=$verify of=$TDIR/$tfile bs=4096 count=1280 oflag=sync &
	ddpid=$!
	sleep $TIMEOUT  # wait for the io to become redo io
	if ! ps -p $ddpid  > /dev/null 2>&1; then
		error "redo io finished incorrectly"
	fi
	do_facet ost1 "lctl set_param fail_loc=0"
	wait $ddpid || true
	cancel_lru_locks osc
	cmp $verify $TDIR/$tfile || error "compare $verify $TDIR/$tfile failed"
	rm -f $verify $TDIR/$tfile
	message=$(dmesg | grep "redo for recoverable error -115")
	[ -z "$message" ] || error "redo error messages found in dmesg"
}
run_test 8a "Verify redo io: redo io when get -EINPROGRESS error"

test_8b() {
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.3.0) ]] ||
		{ skip "Need MDS version at least 2.3.0"; return; }
	verify=$ROOT/tmp/verify-$$
	dd if=/dev/urandom of=$verify bs=4096 count=1280 ||
		error "Create verify file failed"
	#define OBD_FAIL_OST_DQACQ_NET 0x230
	do_facet ost1 "lctl set_param fail_loc=0x230"
	dd if=$verify of=$TDIR/$tfile bs=4096 count=1280 oflag=sync &
	ddpid=$!
	sleep $TIMEOUT  # wait for the io to become redo io
	fail ost1
	do_facet ost1 "lctl set_param fail_loc=0"
	wait $ddpid || error "dd did not complete"
	cancel_lru_locks osc
	cmp $verify $TDIR/$tfile || error "compare $verify $TDIR/$tfile failed"
	rm -f $verify $TDIR/$tfile
}
run_test 8b "Verify redo io: redo io should success after recovery"

test_8c() {
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.3.0) ]] ||
		{ skip "Need MDS version at least 2.3.0"; return; }
	verify=$ROOT/tmp/verify-$$
	dd if=/dev/urandom of=$verify bs=4096 count=1280 ||
		error "Create verify file failed"
	#define OBD_FAIL_OST_DQACQ_NET 0x230
	do_facet ost1 "lctl set_param fail_loc=0x230"
	dd if=$verify of=$TDIR/$tfile bs=4096 count=1280 oflag=sync &
	ddpid=$!
	sleep $TIMEOUT  # wait for the io to become redo io
	ost_evict_client
	# allow recovery to complete
	sleep $((TIMEOUT + 2))
	do_facet ost1 "lctl set_param fail_loc=0"
	wait $ddpid
	cancel_lru_locks osc
	cmp $verify $TDIR/$tfile && error "compare files should fail"
	rm -f $verify $TDIR/$tfile
}
run_test 8c "Verify redo io: redo io should fail after eviction"

test_8d() {
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.3.0) ]] ||
		{ skip "Need MDS version at least 2.3.0"; return; }
	#define OBD_FAIL_MDS_DQACQ_NET 0x187
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x187"
	# test the non-intent create path
	mcreate $TDIR/$tfile &
	cpid=$!
	sleep $TIMEOUT
	if ! ps -p $cpid  > /dev/null 2>&1; then
		error "mknod finished incorrectly"
	fi
	do_facet $SINGLEMDS "lctl set_param fail_loc=0"
	wait $cpid || error "mcreate did not complete"
	stat $TDIR/$tfile || error "mknod failed"

	rm $TDIR/$tfile

	#define OBD_FAIL_MDS_DQACQ_NET 0x187
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x187"
	# test the intent create path
	openfile -f O_RDWR:O_CREAT $TDIR/$tfile &
	cpid=$!
	sleep $TIMEOUT
	if ! ps -p $cpid > /dev/null 2>&1; then
		error "open finished incorrectly"
	fi
	do_facet $SINGLEMDS "lctl set_param fail_loc=0"
	wait $cpid || error "openfile failed"
	stat $TDIR/$tfile || error "open failed"
}
run_test 8d "Verify redo creation on -EINPROGRESS"

test_8e() {
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.3.0) ]] ||
		{ skip "Need MDS version at least 2.3.0"; return; }
	sleep 1 # ensure we have a fresh statfs
	#define OBD_FAIL_OST_STATFS_EINPROGRESS 0x231
	do_facet ost1 "lctl set_param fail_loc=0x231"
	$LFS df $MOUNT &
	dfpid=$!
	sleep $TIMEOUT
	if ! ps -p $dfpid  > /dev/null 2>&1; then
		do_facet ost1 "lctl set_param fail_loc=0"
		error "df shouldn't have completed!"
	fi
}
run_test 8e "Verify that ptlrpc resends request on -EINPROGRESS"

test_9() {
	[ $(lustre_version_code ost1) -ge $(version_code 2.6.54) ] ||
		{ skip "Need OST version at least 2.6.54"; return; }
	$SETSTRIPE -i 0 -c 1 $DIR/$tfile || error "setstripe failed"

	# LU-1573 - Add duplicate write to generate grants
	dd if=/dev/zero of=$DIR/$tfile count=1 bs=1M > /dev/null ||
		error "First write failed"
	replay_barrier ost1
	# do IO
	dd if=/dev/zero of=$DIR/$tfile count=1 bs=1M > /dev/null ||
		error "failed to write"
	# failover, replay and resend replayed waiting request
	#define OBD_FAIL_TGT_REPLAY_DELAY2       0x714
	do_facet ost1 $LCTL set_param fail_loc=0x00000714
	do_facet ost1 $LCTL set_param fail_val=$TIMEOUT
	fail ost1
	do_facet ost1 $LCTL set_param fail_loc=0
	do_facet ost1 "dmesg | tail -n 100" |
		sed -n '/no req deadline/,$ p' | grep -q 'Already past' &&
		return 1
	return 0
}
run_test 9 "Verify that no req deadline happened during recovery"

test_10() {
	rm -f $TDIR/$tfile

	dd if=/dev/zero of=$TDIR/$tfile count=10 || error "dd failed"

	#define OBD_FAIL_OSC_DELAY_IO            0x414
	$LCTL set_param fail_val=60 fail_loc=0x414
	cancel_lru_locks OST0000-osc &
	sleep 2
	facet_failover ost1 || error "failover: $?"

	#define OBD_FAIL_LDLM_GRANT_CHECK        0x32a
	$LCTL set_param fail_loc=0x32a
	stat $TDIR/$tfile

	wait
}
run_test 10 "conflicting PW & PR locks on a client"

complete $SECONDS
check_and_cleanup_lustre
exit_status
