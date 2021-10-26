#!/bin/bash

set -e

ONLY=${ONLY:-"$*"}

SRCDIR=$(dirname $0)
PTLDEBUG=${PTLDEBUG:--1}
LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

#                                  tool to create lustre filesystem images
ALWAYS_EXCEPT="$CONF_SANITY_EXCEPT 32newtarball"

# bug number for skipped test: LU-11915
ALWAYS_EXCEPT="$ALWAYS_EXCEPT  110 115"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

if $SHARED_KEY; then
	# bug number for skipped tests: LU-9795	(all below)
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT   84      86      103"
fi

if ! combined_mgs_mds; then
	# bug number for skipped test: LU-11991		LU-11990
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT  32a 32b 32c 32d 32e	66"
	# bug number for skipped test: LU-9897	LU-12032
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT  84	123F"
fi

#                                  8  22  40  165  (min)
[ "$SLOW" = "no" ] && EXCEPT_SLOW="45 69 106 111"

build_test_filter

# use small MDS + OST size to speed formatting time
# do not use too small MDSSIZE/OSTSIZE, which affect the default journal size
# STORED_MDSSIZE is used in test_18
STORED_MDSSIZE=$MDSSIZE
STORED_OSTSIZE=$OSTSIZE
MDSSIZE=200000
[ "$mds1_FSTYPE" = zfs ] && MDSSIZE=400000
OSTSIZE=200000
[ "$ost1_FSTYPE" = zfs ] && OSTSIZE=400000

fs2mds_HOST=$mds_HOST
fs2ost_HOST=$ost_HOST
fs3ost_HOST=$ost_HOST

MDSDEV1_2=$fs2mds_DEV
OSTDEV1_2=$fs2ost_DEV
OSTDEV2_2=$fs3ost_DEV

# pass "-E lazy_itable_init" to mke2fs to speed up the formatting time
if [[ "$LDISKFS_MKFS_OPTS" != *lazy_itable_init* ]]; then
	LDISKFS_MKFS_OPTS=$(csa_add "$LDISKFS_MKFS_OPTS" -E lazy_itable_init)
fi

#
require_dsh_mds || exit 0
require_dsh_ost || exit 0

assert_DIR

gen_config() {
	# The MGS must be started before the OSTs for a new fs, so start
	# and stop to generate the startup logs.
	start_mds
	start_ost
	wait_osc_import_state mds ost FULL
	stop_ost
	stop_mds
}

reformat_and_config() {
	reformat
	if ! combined_mgs_mds ; then
		start_mgs
	fi
	gen_config
}

writeconf_or_reformat() {
	# There are at most 2 OSTs for write_conf test
	# who knows if/where $TUNEFS is installed?
	# Better reformat if it fails...
	writeconf_all $MDSCOUNT 2 ||
		{ echo "tunefs failed, reformatting instead" &&
		  reformat_and_config && return 0; }
	return 0
}

reformat() {
	formatall
}

start_mgs () {
	echo "start mgs service on $(facet_active_host mgs)"
	start mgs $(mgsdevname) $MGS_MOUNT_OPTS $@
}

start_mdt() {
	local num=$1
	local facet=mds$num
	local dev=$(mdsdevname $num)
	shift 1

	echo "start mds service on `facet_active_host $facet`"
	start $facet ${dev} $MDS_MOUNT_OPTS $@ || return 94
}

stop_mdt_no_force() {
	local num=$1
	local facet=mds$num
	local dev=$(mdsdevname $num)
	shift 1

	echo "stop mds service on `facet_active_host $facet`"
	stop $facet || return 97
}

stop_mdt() {
	local num=$1
	local facet=mds$num
	local dev=$(mdsdevname $num)
	shift 1

	echo "stop mds service on `facet_active_host $facet`"
	# These tests all use non-failover stop
	stop $facet -f || return 97
}

start_mds() {
	local num

	for num in $(seq $MDSCOUNT); do
		start_mdt $num $@ || return 94
	done
	for num in $(seq $MDSCOUNT); do
		wait_clients_import_state ${CLIENTS:-$HOSTNAME} mds${num} FULL
	done
}

start_mgsmds() {
	if ! combined_mgs_mds ; then
		start_mgs
	fi
	start_mds $@
}

stop_mds() {
	local num
	for num in $(seq $MDSCOUNT); do
		stop_mdt $num || return 97
	done
}

stop_mgs() {
	echo "stop mgs service on `facet_active_host mgs`"
	# These tests all use non-failover stop
	stop mgs -f  || return 97
}

start_ost() {
	echo "start ost1 service on `facet_active_host ost1`"
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS $@ || return 95
	wait_clients_import_state ${CLIENTS:-$HOSTNAME} ost1 FULL
}

stop_ost() {
	echo "stop ost1 service on `facet_active_host ost1`"
	# These tests all use non-failover stop
	stop ost1 -f || return 98
}

start_ost2() {
	echo "start ost2 service on `facet_active_host ost2`"
	start ost2 $(ostdevname 2) $OST_MOUNT_OPTS $@ || return 92
	wait_clients_import_state ${CLIENTS:-$HOSTNAME} ost2 FULL
}

stop_ost2() {
	echo "stop ost2 service on `facet_active_host ost2`"
	# These tests all use non-failover stop
	stop ost2 -f || return 93
}

mount_client() {
	local mountpath=$1
	local mountopt="$2"

	echo "mount $FSNAME ${mountopt:+with opts $mountopt} on $mountpath....."
	zconf_mount $HOSTNAME $mountpath $mountopt || return 96
}

umount_client() {
	local mountpath=$1
	shift
	echo "umount lustre on $mountpath....."
	zconf_umount $HOSTNAME $mountpath $@ || return 97
}

manual_umount_client(){
	local rc
	local FORCE=$1
	echo "manual umount lustre on ${MOUNT}...."
	do_facet client "umount ${FORCE} $MOUNT"
	rc=$?
	return $rc
}

setup() {
	start_mds || error "MDT start failed"
	start_ost || error "Unable to start OST1"
	mount_client $MOUNT || error "client start failed"
	client_up || error "client_up failed"
}

setup_noconfig() {
	start_mgsmds
	start_ost
	mount_client $MOUNT
}

unload_modules_conf () {
	if combined_mgs_mds || ! local_mode; then
		unload_modules || return 1
	fi
}

cleanup_nocli() {
	stop_ost || return 202
	stop_mds || return 201
	unload_modules_conf || return 203
}

cleanup() {
	local force=""
	[ "x$1" != "x" ] && force='-f'
	umount_client $MOUNT $force|| return 200
	cleanup_nocli || return $?
}

cleanup_fs2() {
	trap 0
	echo "umount $MOUNT2 ..."
	umount $MOUNT2 || true
	echo "stopping fs2mds ..."
	stop fs2mds -f || true
	echo "stopping fs2ost ..."
	stop fs2ost -f || true
}

check_mount() {
	do_facet client "cp /etc/passwd $DIR/a" || return 71
	do_facet client "rm $DIR/a" || return 72
	# make sure lustre is actually mounted (touch will block,
	# but grep won't, so do it after)
	do_facet client "grep $MOUNT' ' /proc/mounts > /dev/null" || return 73
	echo "setup single mount lustre success"
}

check_mount2() {
	do_facet client "touch $DIR/a" || return 71
	do_facet client "rm $DIR/a" || return 72
	do_facet client "touch $DIR2/a" || return 73
	do_facet client "rm $DIR2/a" || return 74
	echo "setup double mount lustre success"
}

generate_name() {
	cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $1 | head -n 1
}

if [ "$ONLY" == "setup" ]; then
	setup
	exit
fi

if [ "$ONLY" == "cleanup" ]; then
	cleanup
	exit
fi

init_gss

#create single point mountpoint

reformat_and_config

test_0() {
	setup
	check_mount || error "check_mount failed"
	cleanup || error "cleanup failed with $?"
}
run_test 0 "single mount setup"

test_1() {
	start_mds || error "MDS start failed"
	start_ost || error "unable to start OST"
	echo "start ost second time..."
	start_ost && error "2nd OST start should fail"
	mount_client $MOUNT || error "client start failed"
	check_mount || error "check_mount failed"
	cleanup || error "cleanup failed with $?"
}
run_test 1 "start up ost twice (should return errors)"

test_2() {
	start_mds || error "MDT start failed"
	echo "start mds second time.."
	start_mds && error "2nd MDT start should fail"
	start_ost || error "OST start failed"
	mount_client $MOUNT || error "mount_client failed to start client"
	check_mount || error "check_mount failed"
	cleanup || error "cleanup failed with $?"
}
run_test 2 "start up mds twice (should return err)"

test_3() {
	setup
	#mount.lustre returns an error if already in mtab
	mount_client $MOUNT && error "2nd client mount should fail"
	check_mount || error "check_mount failed"
	cleanup || error "cleanup failed with $?"
}
run_test 3 "mount client twice (should return err)"

test_4() {
	setup
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"
	stop_ost || error "Unable to stop OST1"
	umount_client $MOUNT -f || error “unmount $MOUNT failed”
	cleanup_nocli
	eno=$?
	# ok for ost to fail shutdown
	if [ 202 -ne $eno ] && [ 0 -ne $eno ]; then
		error "cleanup failed with $?"
	fi
}
run_test 4 "force cleanup ost, then cleanup"

test_5a() {	# was test_5
	setup
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"
	fuser -m -v $MOUNT && echo "$MOUNT is in use by user space process."

	stop_mds || error "Unable to stop MDS"

	# cleanup may return an error from the failed
	# disconnects; for now I'll consider this successful
	# if all the modules have unloaded.
	$UMOUNT -f $MOUNT &
	UMOUNT_PID=$!
	sleep 6
	echo "killing umount"
	kill -TERM $UMOUNT_PID
	echo "waiting for umount to finish"
	wait $UMOUNT_PID
	if grep " $MOUNT " /proc/mounts; then
		echo "test 5: /proc/mounts after failed umount"
		umount -f $MOUNT &
		UMOUNT_PID=$!
		sleep 2
		echo "killing umount"
		kill -TERM $UMOUNT_PID
		echo "waiting for umount to finish"
		wait $UMOUNT_PID
		grep " $MOUNT " /proc/mounts &&
			error "/proc/mounts after second umount"
	fi

	# manual_mount_client may fail due to umount succeeding above
	manual_umount_client
	# stop_mds is a no-op here, and should not fail
	cleanup_nocli || error "cleanup_nocli failed with $?"
	# df may have lingering entry
	manual_umount_client
	# mtab may have lingering entry
	local WAIT=0
	local MAX_WAIT=20
	local sleep=1
	while [ "$WAIT" -ne "$MAX_WAIT" ]; do
		sleep $sleep
		grep -q $MOUNT" " /etc/mtab || break
		echo "Waiting /etc/mtab updated ... "
		WAIT=$(( WAIT + sleep))
	done
	[ "$WAIT" -eq "$MAX_WAIT" ] &&
		error "/etc/mtab is not updated in $WAIT secs"
	echo "/etc/mtab updated in $WAIT secs"
}
run_test 5a "force cleanup mds, then cleanup"

cleanup_5b () {
	trap 0
	start_mgs
}

test_5b() {
	grep " $MOUNT " /etc/mtab &&
		error false "unexpected entry in mtab before mount" && return 10

	start_ost || error "OST start failed"
	if ! combined_mgs_mds ; then
		trap cleanup_5b EXIT ERR
		start_mds || error "MDS start failed"
		stop mgs
	fi

	mount_client $MOUNT && error "mount_client $MOUNT should fail"
	grep " $MOUNT " /etc/mtab &&
		error "$MOUNT entry in mtab after failed mount"
	umount_client $MOUNT
	# stop_mds is a no-op here, and should not fail
	cleanup_nocli || error "cleanup_nocli failed with $?"
	if ! combined_mgs_mds ; then
		cleanup_5b
	fi
}
run_test 5b "Try to start a client with no MGS (should return errs)"

test_5c() {
	grep " $MOUNT " /etc/mtab &&
		error false "unexpected entry in mtab before mount" && return 10

	start_mds || error "MDS start failed"
	start_ost || error "OST start failed"
	local oldfs="${FSNAME}"
	FSNAME="wrong.${FSNAME}"
	mount_client $MOUNT || :
	FSNAME=${oldfs}
	grep " $MOUNT " /etc/mtab &&
		error "$MOUNT entry in mtab after failed mount"
	umount_client $MOUNT
	cleanup_nocli || error "cleanup_nocli failed with $?"
}
run_test 5c "cleanup after failed mount (bug 2712) (should return errs)"

test_5d() {
	grep " $MOUNT " /etc/mtab &&
		error "unexpected entry in mtab before mount"

	start_ost || error "OST start failed"
	start_mds || error "MDS start failed"
	stop_ost -f || error "Unable to stop OST1"
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	umount_client $MOUNT -f || error "umount_client $MOUNT failed"
	cleanup_nocli || error "cleanup_nocli failed with $?"
	! grep " $MOUNT " /etc/mtab ||
		error "$MOUNT entry in mtab after unmount"
}
run_test 5d "mount with ost down"

test_5e() {
	grep " $MOUNT " /etc/mtab &&
		error false "unexpected entry in mtab before mount" && return 10

	start_mds || error "MDS start failed"
	start_ost || error "OST start failed"

	#define OBD_FAIL_PTLRPC_DELAY_SEND       0x506
	do_facet client "$LCTL set_param fail_loc=0x80000506"
	mount_client $MOUNT || echo "mount failed (not fatal)"
	cleanup || error "cleanup failed with $?"
	grep " $MOUNT " /etc/mtab &&
		error "$MOUNT entry in mtab after unmount"
	pass
}
run_test 5e "delayed connect, don't crash (bug 10268)"

test_5f() {
	combined_mgs_mds && skip "needs separate mgs and mds"

	grep " $MOUNT " /etc/mtab &&
		error false "unexpected entry in mtab before mount" && return 10

	local rc=0
	start_ost || error "OST start failed"
	mount_client $MOUNT &
	local pid=$!
	echo client_mount pid is $pid

	sleep 5

	if ! ps -f -p $pid >/dev/null; then
		wait $pid
		rc=$?
		grep " $MOUNT " /etc/mtab && echo "test 5f: mtab after mount"
		error "mount returns $rc, expected to hang"
		rc=11
		cleanup || error "cleanup failed with $?"
		return $rc
	fi

	# start mds
	start_mds || error "start MDS failed"

	# mount should succeed after start mds
	wait $pid
	grep " $MOUNT " /etc/mtab && echo "test 5f: mtab after mount"
	cleanup || error "final call to cleanup failed with rc $?"
}
run_test 5f "mds down, cleanup after failed mount (bug 2712)"

test_5g() {
	modprobe lustre
	[ "$CLIENT_VERSION" -lt $(version_code 2.9.53) ] &&
		skip "automount of debugfs missing before 2.9.53"
	umount /sys/kernel/debug
	$LCTL get_param -n devices | egrep -v "error" && \
		error "lctl can't access debugfs data"
	grep " debugfs " /etc/mtab || error "debugfs failed to remount"
}
run_test 5g "handle missing debugfs"

test_5h() {
	setup

	stop mds1
	#define OBD_FAIL_MDS_FS_SETUP            0x135
	do_facet mds1 "$LCTL set_param fail_loc=0x80000135"
	start_mdt 1 && error "start mdt should fail"
	start_mdt 1 || error "start mdt failed"
	client_up || error "client_up failed"
	cleanup
}
run_test 5h "start mdt failure at mdt_fs_setup()"

test_5i() {
	(( $MDS1_VERSION >= $(version_code 2.12.54) )) ||
		skip "Need MDS version at least 2.12.54"

	setup

	stop mds1
	#define OBD_FAIL_QUOTA_INIT              0xA05
	do_facet mds1 "$LCTL set_param fail_loc=0x80000A05"
	start_mdt 1 && error "start mdt should fail"
	start_mdt 1 || error "start mdt failed"
	client_up || error "client_up failed"
	cleanup
}
run_test 5i "start mdt failure at mdt_quota_init()"

test_6() {
	setup
	manual_umount_client
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"
	cleanup || error "cleanup failed with rc $?"
}
run_test 6 "manual umount, then mount again"

test_7() {
	setup
	manual_umount_client
	cleanup_nocli || error "cleanup_nocli failed with $?"
}
run_test 7 "manual umount, then cleanup"

test_8() {
	setup
	mount_client $MOUNT2 || error "mount_client $MOUNT2 failed"
	check_mount2 || error "check_mount2 failed"
	umount_client $MOUNT2 || error "umount_client $MOUNT2 failed"
	cleanup || error "cleanup failed with rc $?"
}
run_test 8 "double mount setup"

test_9() {
	start_ost || error "OST start failed"

	do_facet ost1 $LCTL set_param debug=\'inode trace\' ||
		error "do_facet ost1 set_param inode trace failed."
	do_facet ost1 $LCTL set_param subsystem_debug=\'mds ost\' ||
		error "do_facet ost1 set_param debug mds ost failed."

	CHECK_PTLDEBUG="`do_facet ost1 $LCTL get_param -n debug`"
	if [ "$CHECK_PTLDEBUG" ] && { \
	   [ "$CHECK_PTLDEBUG" = "trace inode warning error emerg console" ] ||
	   [ "$CHECK_PTLDEBUG" = "trace inode" ]; }; then
		echo "lnet.debug success"
	else
		error "lnet.debug: want 'trace inode', have '$CHECK_PTLDEBUG'"
	fi
	CHECK_SUBSYS="`do_facet ost1 $LCTL get_param -n subsystem_debug`"
	if [ "$CHECK_SUBSYS" ] && [ "$CHECK_SUBSYS" = "mds ost" ]; then
		echo "lnet.subsystem_debug success"
	else
		error "lnet.subsystem_debug: want 'mds ost' got '$CHECK_SUBSYS'"
	fi
	stop_ost || error "Unable to stop OST1"
}
run_test 9 "test ptldebug and subsystem for mkfs"

test_10a() {
	setup

	if ! combined_mgs_mds; then
		files=$(do_facet mgs "find /{proc/fs,sys/fs,sys/kernel/debug}/lustre -type l -exec test ! -e {} \; -print")
		[ -z $files ] || echo "MGS $files is a broken symlink"
	fi

	files=$(do_facet mds1 "find /{proc/fs,sys/fs,sys/kernel/debug}/lustre -type l -exec test ! -e {} \; -print")
	[ -z $files ] || echo "MDS $files is a broken symlink"

	files=$(do_facet ost1 "find /{proc/fs,sys/fs,sys/kernel/debug}/lustre -type l -exec test ! -e {} \; -print")
	[ -z $files ] || echo "OSS $files is a broken symlink"

	files=$(do_facet client "find /{proc/fs,sys/fs,sys/kernel/debug}/lustre -type l -exec test ! -e {} \; -print")
	[ -z $files ] || echo "clients $files is a broken symlink"

	cleanup || error "cleanup failed with rc $?"
}
run_test 10a "find lctl param broken symlinks"

#
# Test 16 was to "verify that lustre will correct the mode of OBJECTS".
# But with new MDS stack we don't care about the mode of local objects
# anymore, so this test is removed. See bug 22944 for more details.
#

test_17() {
	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi

	setup
	check_mount || error "check_mount failed"
	cleanup || error "cleanup failed with rc $?"

	echo "Remove mds config log"
	if ! combined_mgs_mds ; then
		stop mgs
	fi

	do_facet mgs "$DEBUGFS -w -R 'unlink CONFIGS/$FSNAME-MDT0000' \
		      $(mgsdevname) || return \$?" ||
		error "do_facet mgs failed with $?"

	if ! combined_mgs_mds ; then
		start_mgs
	fi

	start_ost || error "OST start failed"
	start_mds && error "MDS start succeeded, but should fail"
	reformat_and_config
}
run_test 17 "Verify failed mds_postsetup won't fail assertion (2936) (should return errs)"

test_18() {
	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi

	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})

	local MIN=2000000

	local OK=
	# check if current MDSSIZE is large enough
	[ $MDSSIZE -ge $MIN ] && OK=1 && myMDSSIZE=$MDSSIZE &&
		log "use MDSSIZE=$MDSSIZE"

	# check if the global config has a large enough MDSSIZE
	[ -z "$OK" -a ! -z "$STORED_MDSSIZE" ] &&
		[ $STORED_MDSSIZE -ge $MIN ] &&
		OK=1 && myMDSSIZE=$STORED_MDSSIZE &&
		log "use STORED_MDSSIZE=$STORED_MDSSIZE"

	# check if the block device is large enough
	is_blkdev $SINGLEMDS $MDSDEV $MIN
	local large_enough=$?
	if [ -n "$OK" ]; then
		[ $large_enough -ne 0 ] && OK=""
	else
		[ $large_enough -eq 0 ] && OK=1 && myMDSSIZE=$MIN &&
			log "use device $MDSDEV with MIN=$MIN"
	fi

	# check if a loopback device has enough space for fs metadata (5%)

	if [ -z "$OK" ]; then
		local SPACE=$(do_facet $SINGLEMDS "[ -f $MDSDEV -o ! \
			      -e $MDSDEV ] && df -P \\\$(dirname $MDSDEV)" |
			awk '($1 != "Filesystem") { print $4 }')
		! [ -z "$SPACE" ] && [ $SPACE -gt $((MIN / 20)) ] &&
			OK=1 && myMDSSIZE=$MIN &&
			log "use file $MDSDEV with MIN=$MIN"
	fi

	[ -z "$OK" ] && skip_env "$MDSDEV too small for ${MIN}kB MDS"

	echo "mount mds with large journal..."

	local OLD_MDSSIZE=$MDSSIZE
	MDSSIZE=$myMDSSIZE

	reformat_and_config
	echo "mount lustre system..."
	setup
	check_mount || error "check_mount failed"

        echo "check journal size..."
        local FOUNDSIZE=$(do_facet $SINGLEMDS "$DEBUGFS -c -R 'stat <8>' $MDSDEV" | awk '/Size: / { print $NF; exit;}')
        if [ $FOUNDSIZE -gt $((32 * 1024 * 1024)) ]; then
                log "Success: mkfs creates large journals. Size: $((FOUNDSIZE >> 20))M"
        else
                error "expected journal size > 32M, found $((FOUNDSIZE >> 20))M"
        fi

	cleanup || error "cleanup failed with rc $?"

	MDSSIZE=$OLD_MDSSIZE
	reformat_and_config
}
run_test 18 "check mkfs creates large journals"

test_19a() {
	start_mds || error "MDS start failed"
	stop_mds || error "Unable to stop MDS"
}
run_test 19a "start/stop MDS without OSTs"

test_19b() {
	start_ost || error "Unable to start OST1"
	stop_ost -f || error "Unable to stop OST1"
}
run_test 19b "start/stop OSTs without MDS"

test_20() {
	# first format the ost/mdt
	start_mds || error "MDS start failed"
	start_ost || error "Unable to start OST1"
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	check_mount || error "check_mount failed"
	rm -f $DIR/$tfile || error "remove $DIR/$tfile failed."
	mount_client $MOUNT remount,ro || error "remount client with ro failed"
	touch $DIR/$tfile && error "$DIR/$tfile created incorrectly"
	[ -e $DIR/$tfile ] && error "$DIR/$tfile exists incorrectly"
	mount_client $MOUNT remount,rw || error "remount client with rw failed"
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"
	MCNT=$(grep -c $MOUNT' ' /etc/mtab)
	[ "$MCNT" -ne 1 ] && error "$MOUNT in /etc/mtab $MCNT times"
	umount_client $MOUNT
	stop_mds || error "Unable to stop MDS"
	stop_ost || error "Unable to stop OST1"
}
run_test 20 "remount ro,rw mounts work and doesn't break /etc/mtab"

test_21a() {
	start_mds || error "MDS start failed"
	start_ost || error "unable to start OST1"
	wait_osc_import_state mds ost FULL
	stop_ost || error "unable to stop OST1"
	stop_mds || error "unable to stop MDS"
}
run_test 21a "start mds before ost, stop ost first"

test_21b() {
	start_ost || error "unable to start OST1"
	start_mds || error "MDS start failed"
	wait_osc_import_state mds ost FULL
	stop_mds || error "unable to stop MDS"
	stop_ost || error "unable to stop OST1"
}
run_test 21b "start ost before mds, stop mds first"

test_21c() {
	start_ost || error "Unable to start OST1"
	start_mds || error "MDS start failed"
	start_ost2 || error "Unable to start OST2"
	wait_osc_import_state mds ost2 FULL
	stop_ost || error "Unable to stop OST1"
	stop_ost2 || error "Unable to stop OST2"
	stop_mds || error "Unable to stop MDS"
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 21c "start mds between two osts, stop mds last"

test_21d() {
	combined_mgs_mds && skip "need separate mgs device"

	stopall
	reformat

	start_mgs || error "unable to start MGS"
	start_ost || error "unable to start OST1"
	start_ost2 || error "unable to start OST2"
	start_mds || error "MDS start failed"
	wait_osc_import_state mds ost2 FULL

	local zkeeper=${KEEP_ZPOOL}
	stack_trap "KEEP_ZPOOL=$zkeeper" EXIT
	KEEP_ZPOOL="true"

	stop_ost || error "Unable to stop OST1"
	stop_ost2 || error "Unable to stop OST2"
	stop_mds || error "Unable to stop MDS"
	stop_mgs
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
	KEEP_ZPOOL="${zkeeper}"

	start_mgs || error "unable to start MGS"
}
run_test 21d "start mgs then ost and then mds"

cleanup_21e() {
	MGSNID="$saved_mgsnid"
	cleanup_fs2
	echo "stopping fs2mgs ..."
	stop $fs2mgs -f || true
}

test_21e() { # LU-5863
	if [[ -z "$fs3ost_DEV" || -z "$fs2ost_DEV" || -z "$fs2mds_DEV" ]]; then
		is_blkdev $SINGLEMDS $(mdsdevname ${SINGLEMDS//mds/}) &&
		skip_env "mixed loopback and real device not working"
	fi

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2ostdev=$(ostdevname 1_2)
	local fs3ostdev=$(ostdevname 2_2)

	local fs2mdsvdev=$(mdsvdevname 1_2)
	local fs2ostvdev=$(ostvdevname 1_2)
	local fs3ostvdev=$(ostvdevname 2_2)

	# temporarily use fs3ost as fs2mgs
	local fs2mgs=fs3ost
	local fs2mgsdev=$fs3ostdev
	local fs2mgsvdev=$fs3ostvdev

	local fsname=test1234

	add $fs2mgs $(mkfs_opts mgs $fs2mgsdev) --fsname=$fsname \
		--reformat $fs2mgsdev $fs2mgsvdev || error "add fs2mgs failed"
	start $fs2mgs $fs2mgsdev $MGS_MOUNT_OPTS && trap cleanup_21e EXIT INT ||
		error "start fs2mgs failed"

	local saved_mgsnid="$MGSNID"
	MGSNID=$(do_facet $fs2mgs $LCTL list_nids | xargs | tr ' ' ,)

	add fs2mds $(mkfs_opts mds1 $fs2mdsdev $fsname) \
		--reformat $fs2mdsdev $fs2mdsvdev || error "add fs2mds failed"
	add fs2ost $(mkfs_opts ost1 $fs2ostdev $fsname) \
		--reformat $fs2ostdev $fs2ostvdev || error "add fs2ost failed"

	start fs2ost $fs2ostdev $OST_MOUNT_OPTS || error "start fs2ost failed"
	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS || error "start fs2mds failed"

	mkdir -p $MOUNT2 || error "mkdir $MOUNT2 failed"
	$MOUNT_CMD $MGSNID:/$fsname $MOUNT2 || error "mount $MOUNT2 failed"
	DIR=$MOUNT2 MOUNT=$MOUNT2 check_mount || error "check $MOUNT2 failed"

	cleanup_21e
}
run_test 21e "separate MGS and MDS"

test_22() {
	start_mds || error "MDS start failed"

	echo "Client mount with ost in logs, but none running"
	start_ost || error "unable to start OST1"
	# wait until mds connected to ost and open client connection
	wait_osc_import_state mds ost FULL
	stop_ost || error "unable to stop OST1"
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	# check_mount will block trying to contact ost
	mcreate $DIR/$tfile || error "mcreate $DIR/$tfile failed"
	rm -f $DIR/$tfile || error "remove $DIR/$tfile failed"
	umount_client $MOUNT -f
	pass

	echo "Client mount with a running ost"
	start_ost || error "unable to start OST1"
	if $GSS; then
		# if gss enabled, wait full time to let connection from
		# mds to ost be established, due to the mismatch between
		# initial connect timeout and gss context negotiation timeout.
		# This perhaps could be remove after AT landed.
		echo "sleep $((TIMEOUT + TIMEOUT + TIMEOUT))s"
		sleep $((TIMEOUT + TIMEOUT + TIMEOUT))
	fi
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	wait_osc_import_state mds ost FULL
	wait_osc_import_ready client ost
	check_mount || error "check_mount failed"
	pass

	cleanup || error "cleanup failed with rc $?"
}
run_test 22 "start a client before osts (should return errs)"

test_23a() {	# was test_23
	setup
	# fail mds
	stop $SINGLEMDS || error "failed to stop $SINGLEMDS"
	# force down client so that recovering mds waits for reconnect
	local running=$(grep -c $MOUNT /proc/mounts) || true
	if [ $running -ne 0 ]; then
		echo "Stopping client $MOUNT (opts: -f)"
		umount -f $MOUNT
	fi

	# enter recovery on failed mds
	local MDT_DEV=$(mdsdevname ${SINGLEMDS//mds/})
	start $SINGLEMDS $MDT_DEV $MDS_MOUNT_OPTS || error "MDS start failed"
	# try to start a new client
	mount_client $MOUNT &
	sleep 5
	MOUNT_PID=$(ps -ef | grep "t lustre" | grep -v grep | awk '{print $2}')
	MOUNT_LUSTRE_PID=$(ps -ef | grep mount.lustre |
			   grep -v grep | awk '{print $2}')
	echo mount pid is ${MOUNT_PID}, mount.lustre pid is ${MOUNT_LUSTRE_PID}
	ps --ppid $MOUNT_PID
	ps --ppid $MOUNT_LUSTRE_PID
	echo "waiting for mount to finish"
	ps -ef | grep mount
	# "ctrl-c" sends SIGINT but it usually (in script) does not work on child process
	# SIGTERM works but it does not spread to offspring processses
	kill -s TERM $MOUNT_PID
	kill -s TERM $MOUNT_LUSTRE_PID
	# we can not wait $MOUNT_PID because it is not a child of this shell
	local PID1
	local PID2
	local WAIT=0
	local MAX_WAIT=30
	local sleep=1
	while [ "$WAIT" -lt "$MAX_WAIT" ]; do
		sleep $sleep
		PID1=$(ps -ef | awk '{print $2}' | grep -w $MOUNT_PID)
		PID2=$(ps -ef | awk '{print $2}' | grep -w $MOUNT_LUSTRE_PID)
		echo PID1=$PID1
		echo PID2=$PID2
		[ -z "$PID1" -a -z "$PID2" ] && break
		echo "waiting for mount to finish ... "
		WAIT=$(( WAIT + sleep))
	done
	if [ "$WAIT" -eq "$MAX_WAIT" ]; then
		error "MOUNT_PID $MOUNT_PID and "\
		"MOUNT_LUSTRE_PID $MOUNT_LUSTRE_PID still not killed in $WAIT secs"
		ps -ef | grep mount
	fi
	cleanup || error "cleanup failed with rc $?"
}
run_test 23a "interrupt client during recovery mount delay"

test_23b() {    # was test_23
	start_mds || error "MDS start failed"
	start_ost || error "Unable to start OST1"
	# Simulate -EINTR during mount OBD_FAIL_LDLM_CLOSE_THREAD
	$LCTL set_param fail_loc=0x80000313
	mount_client $MOUNT
	cleanup || error "cleanup failed with rc $?"
}
run_test 23b "Simulate -EINTR during mount"

test_24a() {
	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})

	if [ -z "$fs2ost_DEV" -o -z "$fs2mds_DEV" ]; then
		is_blkdev $SINGLEMDS $MDSDEV &&
		skip_env "mixed loopback and real device not working"
	fi

	[ -n "$ost1_HOST" ] && fs2ost_HOST=$ost1_HOST

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2ostdev=$(ostdevname 1_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)
	local fs2ostvdev=$(ostvdevname 1_2)
	local cl_user

	# LU-9733 test fsname started with numbers as well
	local FSNAME2=969362ae

	add fs2mds $(mkfs_opts mds1 ${fs2mdsdev} ) --nomgs --mgsnode=$MGSNID \
		--fsname=${FSNAME2} --reformat $fs2mdsdev $fs2mdsvdev || exit 10

	add fs2ost $(mkfs_opts ost1 ${fs2ostdev}) --fsname=${FSNAME2} \
		--reformat $fs2ostdev $fs2ostvdev || exit 10

	setup
	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS && trap cleanup_fs2 EXIT INT
	start fs2ost $fs2ostdev $OST_MOUNT_OPTS
	mkdir -p $MOUNT2 || error "mkdir $MOUNT2 failed"
	$MOUNT_CMD $MGSNID:/${FSNAME2} $MOUNT2 || error "$MOUNT_CMD failed"

	# LU-9733 test fsname started with numbers
	cl_user=$(do_facet $SINGLEMDS lctl --device $FSNAME2-MDT0000 \
			changelog_register -n) ||
				error "register changelog failed"

	do_facet $SINGLEMDS lctl --device $FSNAME2-MDT0000 \
			changelog_deregister $cl_user ||
				error "deregister changelog failed"
	# 1 still works
	check_mount || error "check_mount failed"
	# files written on 1 should not show up on 2
	cp /etc/passwd $DIR/$tfile
	sleep 10
	[ -e $MOUNT2/$tfile ] && error "File bleed"
	# 2 should work
	sleep 5
	cp /etc/passwd $MOUNT2/$tfile ||
		error "cp /etc/passwd $MOUNT2/$tfile failed"
	rm $MOUNT2/$tfile || error "remove $MOUNT2/$tfile failed"
	# 2 is actually mounted
	grep $MOUNT2' ' /proc/mounts > /dev/null || error "$MOUNT2 not mounted"
	# failover
	facet_failover fs2mds
	facet_failover fs2ost
	df
	umount_client $MOUNT
	# the MDS must remain up until last MDT
	stop_mds
	MDS=$(do_facet $SINGLEMDS "$LCTL get_param -n devices" |
	      awk '($3 ~ "mdt" && $4 ~ "MDT") { print $4 }' | head -1)
	[ -z "$MDS" ] && error "No MDT"
	cleanup_fs2
	cleanup_nocli || error "cleanup_nocli failed with rc $?"
}
run_test 24a "Multiple MDTs on a single node"

test_24b() {
	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})
	combined_mgs_mds ||
		skip "needs combined MGT and MDT device"

	if [ -z "$fs2mds_DEV" ]; then
		local dev=${SINGLEMDS}_dev
		local MDSDEV=${!dev}
		is_blkdev $SINGLEMDS $MDSDEV &&
		skip_env "mixed loopback and real device not working"
	fi

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)

	add fs2mds $(mkfs_opts mds1 ${fs2mdsdev} ) --mgs --fsname=${FSNAME}2 \
		--reformat $fs2mdsdev $fs2mdsvdev || exit 10
	setup
	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS && {
		cleanup
		error "start MDS should fail"
	}
	stop fs2mds -f
	cleanup || error "cleanup failed with rc $?"
}
run_test 24b "Multiple MGSs on a single node (should return err)"

test_25() {
	setup_noconfig
	check_mount || error "check_mount failed"
	local MODULES=$($LCTL modules | awk '{ print $2 }')
	rmmod $MODULES 2>/dev/null || true
	cleanup || error "cleanup failed with $?"
}
run_test 25 "Verify modules are referenced"

test_26() {
	load_modules
	# we need modules before mount for sysctl, so make sure...
	do_facet $SINGLEMDS "lsmod | grep -q lustre || modprobe lustre"
	#define OBD_FAIL_MDS_FS_SETUP            0x135
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x80000135"
	start_mds && error "MDS started but should not have started"
	$LCTL get_param -n devices
	DEVS=$($LCTL get_param -n devices | egrep -v MG | wc -l)
	[ $DEVS -gt 0 ] && error "number of devices is $DEVS, should be zero"
	# start mds to drop writeconf setting
	start_mds || error "Unable to start MDS"
	stop_mds || error "Unable to stop MDS"
	unload_modules_conf || error "unload_modules_conf failed with $?"
}
run_test 26 "MDT startup failure cleans LOV (should return errs)"

test_27a() {
	cleanup
	start_ost || error "Unable to start OST1"
	start_mds || error "Unable to start MDS"
	echo "Requeue thread should have started: "
	ps -e | grep ll_cfg_requeue
	set_persistent_param_and_check ost1			\
	   "obdfilter.$FSNAME-OST0000.client_cache_seconds"	\
	   "$FSNAME-OST0000.ost.client_cache_seconds"
	cleanup_nocli || error "cleanup_nocli failed with rc $?"
}
run_test 27a "Reacquire MGS lock if OST started first"

test_27b() {
	# FIXME. ~grev
	setup_noconfig
	local device=$(do_facet $SINGLEMDS "$LCTL get_param -n devices" |
			awk '($3 ~ "mdt" && $4 ~ "MDT0000") { print $4 }')

	facet_failover $SINGLEMDS
	set_persistent_param_and_check $SINGLEMDS	\
		"mdt.$device.identity_acquire_expire"	\
		"$device.mdt.identity_acquire_expire"
	set_persistent_param_and_check client		\
		"mdc.$device-mdc-*.max_rpcs_in_flight"	\
		"$device.mdc.max_rpcs_in_flight"
	check_mount
	cleanup || error "cleanup failed with $?"
}
run_test 27b "Reacquire MGS lock after failover"

test_28A() { # was test_28
	setup_noconfig

	local TEST="llite.$FSNAME-*.max_read_ahead_whole_mb"
	local PARAM="$FSNAME.llite.max_read_ahead_whole_mb"
	local orig=$($LCTL get_param -n $TEST)
	local max=$($LCTL get_param -n \
			llite.$FSNAME-*.max_read_ahead_per_file_mb)

	orig=${orig%%.[0-9]*}
	max=${max%%.[0-9]*}
	echo "ORIG:$orig MAX:$max"
	[[ $max -le $orig ]] && orig=$((max - 3))
	echo "ORIG:$orig MAX:$max"

	local final=$((orig + 1))

	set_persistent_param_and_check client "$TEST" "$PARAM" $final
	final=$((final + 1))
	set_persistent_param_and_check client "$TEST" "$PARAM" $final
	umount_client $MOUNT || error "umount_client $MOUNT failed"
	mount_client $MOUNT || error "mount_client $MOUNT failed"

	local result=$($LCTL get_param -n $TEST)

	if [ $result -ne $final ]; then
		error "New config not seen: wanted $final got $result"
	else
		echo "New config success: got $result"
	fi
	set_persistent_param_and_check client "$TEST" "$PARAM" $orig
	cleanup || error "cleanup failed with rc $?"
}
run_test 28A "permanent parameter setting"

test_28a() { # LU-4221
	[[ "$OST1_VERSION" -ge $(version_code 2.5.52) ]] ||
		skip "Need OST version at least 2.5.52"
	[ "$ost1_FSTYPE" = zfs ] &&
		skip "LU-4221: no such proc params for ZFS OSTs"

	local name
	local param
	local cmd
	local old
	local new
	local device="$FSNAME-OST0000"

	setup_noconfig

	# In this test we will set three kinds of proc parameters with
	# lctl set_param -P or lctl conf_param:
	# 1. non-symlink ones in the OFD
	# 2. non-symlink ones in the OSD

	# Check 1.
	# prepare a non-symlink parameter in the OFD
	name="client_cache_seconds"
	param="$device.ost.$name"
	cmd="obdfilter.$device.$name"

	# permanently setting the parameter in the OFD
	old=$(do_facet ost1 $LCTL get_param -n $cmd)
	new=$((old * 2))
	set_persistent_param_and_check ost1 "$cmd" "$param" $new
	set_persistent_param_and_check ost1 "$cmd" "$param" $old

	# Check 2.
	# prepare a non-symlink parameter in the OSD
	name="auto_scrub"
	param="$device.osd.$name"
	cmd="osd-*.$device.$name"

	# conf_param the parameter in the OSD
	old=$(do_facet ost1 $LCTL get_param -n $cmd)
	new=$(((old + 1) % 2))
	set_persistent_param_and_check ost1 "$cmd" "$param" $new
	set_persistent_param_and_check ost1 "$cmd" "$param" $old

	cleanup || error "cleanup failed with $?"
}
run_test 28a "set symlink parameters permanently with lctl"

test_29() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "needs >= 2 OSTs"
	setup_noconfig > /dev/null 2>&1
	start_ost2 || error "Unable to start OST2"
	sleep 10

	local PARAM="$FSNAME-OST0001.osc.active"
	# With lctl set_param -P the value $PROC_ACT will be sent to
	# all nodes. The [!M] filter out the ability to set active
	# on the MDS servers which is tested with wait_osp_* below.
	# For ost_server_uuid that only exist on client so filtering
	# is safe.
	local PROC_ACT="os[cp].$FSNAME-OST0001-osc-[^M]*.active"
	local PROC_UUID="os[cp].$FSNAME-OST0001-osc-[^M]*.ost_server_uuid"

	ACTV=$($LCTL get_param -n $PROC_ACT)
	DEAC=$((1 - $ACTV))
	set_persistent_param_and_check client $PROC_ACT $PARAM $DEAC
	# also check ost_server_uuid status
	RESULT=$($LCTL get_param -n $PROC_UUID | grep DEACTIV)
	if [ -z "$RESULT" ]; then
		error "Client not deactivated: $($LCTL get_param \
		       -n $PROC_UUID)"
	else
		echo "Live client success: got $RESULT"
	fi

	# check MDTs too
	wait_osp_active ost ${FSNAME}-OST0001 1 0

	# test new client starts deactivated
	umount_client $MOUNT || error "umount_client $MOUNT failed"
	mount_client $MOUNT || error "mount_client $MOUNT failed"

	# the 2nd and 3rd field of ost_server_uuid do not update at the same
	# time when using lctl set_param -P
	wait_update_facet client					\
		"$LCTL get_param -n $PROC_UUID | awk '{print \\\$3 }'"	\
		"DEACTIVATED" ||
		error "New client start active: $($LCTL get_param -n $PROC_UUID)"

	echo "New client success: got '$($LCTL get_param -n $PROC_UUID)'"

	# make sure it reactivates
	set_persistent_param_and_check client $PROC_ACT $PARAM $ACTV

	umount_client $MOUNT
	stop_ost2 || error "Unable to stop OST2"
	cleanup_nocli || error "cleanup_nocli failed with $?"
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 29 "permanently remove an OST"

test_30a() {
	setup_noconfig

	echo Big config llog
	TEST="llite.$FSNAME-*.max_read_ahead_whole_mb"
	ORIG=$($LCTL get_param -n $TEST)
	LIST=(1 2 3 4 5 4 3 2 1 2 3 4 5 4 3 2 1 2 3 4 5)
	for i in ${LIST[@]}; do
		set_persistent_param_and_check client "$TEST" \
			"$FSNAME.llite.max_read_ahead_whole_mb" $i
	done
	# make sure client restart still works
	umount_client $MOUNT
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	[ "$($LCTL get_param -n $TEST)" -ne "$i" ] &&
		error "Param didn't stick across restart $($TEST) != $i"
	pass

	echo Erase parameter setting
	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		do_facet mgs "$PERM_CMD -d $TEST" ||
			error "Erase param $TEST failed"
	else
		do_facet mgs "$PERM_CMD \
			      -d $FSNAME.llite.max_read_ahead_whole_mb" ||
			error "Erase param $FSNAME.llite.max_read_ahead_whole_mb failed"
	fi
	umount_client $MOUNT
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	FINAL=$($LCTL get_param -n $TEST)
	echo "deleted (default) value=$FINAL, orig=$ORIG"
	ORIG=${ORIG%%.[0-9]*}
	FINAL=${FINAL%%.[0-9]*}
	# assumes this parameter started at the default value
	[ "$FINAL" -eq "$ORIG" ] || fail "Deleted value=$FINAL, orig=$ORIG"

	cleanup || error "cleanup failed with rc $?"
}
run_test 30a "Big config llog and permanent parameter deletion"

test_30b() {
	setup_noconfig

	local orignids=$($LCTL get_param -n \
		osc.$FSNAME-OST0000-osc-[^M]*.import | grep failover_nids)

	local orignidcount=$(echo "$orignids" | wc -w)

	# Make a fake nid.  Use the OST nid, and add 20 to the least significant
	# numerical part of it. Hopefully that's not already a failover address
	# for the server.
	local OSTNID=$(do_facet ost1 "$LCTL get_param nis" | tail -1 | \
		awk '{print $1}')
	local ORIGVAL=$(echo $OSTNID | egrep -oi "[0-9]*@")
	local NEWVAL=$((($(echo $ORIGVAL | egrep -oi "[0-9]*") + 20) % 256))
	local NEW=$(echo $OSTNID | sed "s/$ORIGVAL/$NEWVAL@/")
	echo "Using fake nid $NEW"

	local TEST="$LCTL get_param -n osc.$FSNAME-OST0000-osc-[^M]*.import |
		grep failover_nids | sed -n 's/.*\($NEW\).*/\1/p'"
	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		PARAM="osc.$FSNAME-OST0000-osc-[^M]*.import"
		echo "Setting $PARAM from $TEST to $NEW"
		do_facet mgs "$PERM_CMD $PARAM='connection=$NEW'" ||
			error "$PERM_CMD $PARAM failed"
	else
		PARAM="$FSNAME-OST0000.failover.node"
		echo "Setting $PARAM from $TEST to $NEW"
		do_facet mgs "$PERM_CMD $PARAM='$NEW'" ||
			error "$PARAM $PARAM failed"
	fi
	wait_update_facet client "$TEST" "$NEW" ||
		error "check $PARAM failed!"

	local NIDS=$($LCTL get_param -n osc.$FSNAME-OST0000-osc-[^M]*.import |
		grep failover_nids)
	local NIDCOUNT=$(echo "$NIDS" | wc -w)
	echo "should have $((orignidcount + 1)) entries \
		in failover nids string, have $NIDCOUNT"
	[ $NIDCOUNT -eq $((orignidcount + 1)) ] ||
		error "Failover nid not added"

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		do_facet mgs "$PERM_CMD -d osc.$FSNAME-OST0000-osc-*.import"
	else
		do_facet mgs "$PERM_CMD -d $FSNAME-OST0000.failover.node" ||
			error "$PERM_CMD delete failed"
	fi
	umount_client $MOUNT
	mount_client $MOUNT || error "mount_client $MOUNT failed"

	NIDS=$($LCTL get_param -n osc.$FSNAME-OST0000-osc-[^M]*.import |
		grep failover_nids)
	NIDCOUNT=$(echo "$NIDS" | wc -w)
	echo "only $orignidcount final entries should remain \
		in failover nids string, have $NIDCOUNT"
	[ $NIDCOUNT -eq $orignidcount ] || error "Failover nids not removed"

	cleanup || error "cleanup failed with rc $?"
}
run_test 30b "Remove failover nids"

test_31() { # bug 10734
	# ipaddr must not exist
	$MOUNT_CMD 4.3.2.1@tcp:/lustre $MOUNT || true
	cleanup || error "cleanup failed with rc $?"
}
run_test 31 "Connect to non-existent node (shouldn't crash)"


T32_QID=60000
T32_BLIMIT=40960 # Kbytes
T32_ILIMIT=4

#
# This is not really a test but a tool to create new disk
# image tarballs for the upgrade tests.
#
# Disk image tarballs should be created on single-node
# clusters by running this test with default configurations
# plus a few mandatory environment settings that are verified
# at the beginning of the test.
#
test_32newtarball() {
	local version
	local dst=.
	local src=/etc/rc.d
	local tmp=$TMP/t32_image_create
	local remote_dir
	local striped_dir
	local pushd_dir

	if [ $FSNAME != t32fs -o \( -z "$MDSDEV" -a -z "$MDSDEV1" \) -o	\
	     $OSTCOUNT -ne 1 -o	-z "$OSTDEV1" ]; then
		error "Needs FSNAME=t32fs MDSCOUNT=2 "			\
		      "MDSDEV1=<nonexistent_file>"			\
		      "MDSDEV2=<nonexistent_file>"			\
		      "(or MDSDEV, in the case of b1_8)"		\
		      "OSTCOUNT=1 OSTDEV1=<nonexistent_file>"
	fi

	mkdir $tmp || {
		echo "Found stale $tmp"
		return 1
	}

	mkdir $tmp/src || return 1
	tar cf - -C $src . | tar xf - -C $tmp/src
	dd if=/dev/zero of=$tmp/src/t32_qf_old bs=1M \
		count=$(($T32_BLIMIT / 1024 / 4))
	chown $T32_QID.$T32_QID $tmp/src/t32_qf_old

	# format ost with comma-separated NIDs to verify LU-4460
	local failnid="$(h2nettype 1.2.3.4),$(h2nettype 4.3.2.1)"
	MGSNID="$MGSNID,$MGSNID" OSTOPT="--failnode=$failnid" formatall

	setupall

	[[ "$MDS1_VERSION" -ge $(version_code 2.3.50) ]] ||
		$LFS quotacheck -ug /mnt/$FSNAME
	$LFS setquota -u $T32_QID -b 0 -B $T32_BLIMIT -i 0 -I $T32_ILIMIT \
		/mnt/$FSNAME

	tar cf - -C $tmp/src . | tar xf - -C /mnt/$FSNAME

	if [[ $MDSCOUNT -ge 2 ]]; then
		remote_dir=/mnt/$FSNAME/remote_dir
		$LFS mkdir -i 1 $remote_dir
		tar cf - -C $tmp/src . | tar xf - -C $remote_dir

		if [[ "$MDS1_VERSION" -ge $(version_code 2.7.0) ]]; then
			striped_dir=/mnt/$FSNAME/striped_dir_old
			$LFS mkdir -i 1 -c 2 $striped_dir
			tar cf - -C $tmp/src . | tar xf - -C $striped_dir
		fi
	fi

	stopall

	mkdir $tmp/img || return 1

	setupall

	pushd_dir=/mnt/$FSNAME
	if [[ $MDSCOUNT -ge 2 ]]; then
		pushd_dir=$remote_dir
		if [[ "$MDS1_VERSION" -ge $(version_code 2.7.0) ]]; then
			pushd $striped_dir
			ls -Rni --time-style=+%s >$tmp/img/list2
			popd
		fi
	fi

	pushd $pushd_dir
	ls -Rni --time-style=+%s >$tmp/img/list
	find ! -name .lustre -type f -exec sha1sum {} \; |
		sort -k 2 >$tmp/img/sha1sums
	popd
	$LCTL get_param -n version | head -n 1 |
		sed -e 's/^lustre: *//' >$tmp/img/commit

	[[ "$MDS1_VERSION" -ge $(version_code 2.3.50) ]] ||
		$LFS quotaon -ug /mnt/$FSNAME
	$LFS quota -u $T32_QID -v /mnt/$FSNAME
	$LFS quota -v -u $T32_QID /mnt/$FSNAME |
		awk 'BEGIN { num='1' } { if ($1 == "'/mnt/$FSNAME'") \
		{ if (NF == 1) { getline } else { num++ } ; print $num;} }' \
		| tr -d "*" > $tmp/img/bspace
	$LFS quota -v -u $T32_QID /mnt/$FSNAME |
		awk 'BEGIN { num='5' } { if ($1 == "'/mnt/$FSNAME'") \
		{ if (NF == 1) { getline } else { num++ } ; print $num;} }' \
		| tr -d "*" > $tmp/img/ispace
	echo $T32_BLIMIT > $tmp/img/blimit
	echo $T32_ILIMIT > $tmp/img/ilimit

	$MULTIOP /mnt/$FSNAME/orph_file Ouw_c&
	pid=$!
	sync
	stop_mdt_no_force 1
	debugfs -R "ls /PENDING" ${MDSDEV1:-$MDSDEV}
	cp ${MDSDEV1:-$MDSDEV} $tmp/img
	start_mdt 1
	kill -s USR1 $pid
	wait $pid

	stopall

	pushd $tmp/src
	find -type f -exec sha1sum {} \; | sort -k 2 >$tmp/sha1sums.src
	popd

	if ! diff -u $tmp/sha1sums.src $tmp/img/sha1sums; then
		echo "Data verification failed"
	fi

	uname -r >$tmp/img/kernel
	uname -m >$tmp/img/arch

	for num in $(seq 2 $MDSCOUNT); do
		local devname=$(mdsdevname $num)
		local facet=mds$num
		[[ $(facet_fstype $facet) != zfs ]] ||
			devname=$(mdsvdevname $num)
		mv $devname $tmp/img
	done
	mv $OSTDEV1 $tmp/img

	version=$(sed -e 's/\(^[0-9]\+\.[0-9]\+\)\(.*$\)/\1/' $tmp/img/commit |
			  sed -e 's/\./_/g')	# E.g., "1.8.7" -> "1_8"
	dst=$(cd $dst; pwd)
	pushd $tmp/img
	tar cjvf $dst/disk$version-"$mds1_FSTYPE".tar.bz2 -S *
	popd

	rm -r $tmp
}
#run_test 32newtarball "Create a new test_32 disk image tarball for this version"

#
# The list of applicable tarballs is returned via the caller's
# variable "tarballs".
#
t32_check() {
	[ "$CLIENTONLY" ] && skip "Client-only testing"

	local node=$(facet_active_host $SINGLEMDS)
	local r="do_node $node"

	! $r which "$TUNEFS" && skip_env "tunefs.lustre required on $node"

	local IMGTYPE="$mds1_FSTYPE"

	tarballs=$($r find $RLUSTRE/tests -maxdepth 1 \
		   -name \'disk*-$IMGTYPE.tar.bz2\')

	[ -z "$tarballs" ] && skip "No applicable tarballs found"
}

t32_test_cleanup() {
	local tmp=$TMP/t32
	local facet=$SINGLEMDS
	local rc=$?

	if $shall_cleanup_lustre; then
		umount $tmp/mnt/lustre || rc=$?
	fi
	if $shall_cleanup_mdt; then
		$r $UMOUNT $tmp/mnt/mdt || rc=$?
	fi
	if $shall_cleanup_mdt1; then
		$r $UMOUNT $tmp/mnt/mdt1 || rc=$?
	fi
	if $shall_cleanup_ost; then
		$r $UMOUNT $tmp/mnt/ost || rc=$?
	fi

	$r rm -rf $tmp
	rm -rf $tmp
	if [[ "$mds1_FSTYPE" == zfs ]]; then
		local poolname
		local poolname_list="t32fs-mdt1 t32fs-ost1"

		! $mdt2_is_available || poolname_list+=" t32fs-mdt2"

		for poolname in $poolname_list; do
			destroy_zpool $facet $poolname
		done
	fi
	combined_mgs_mds || start_mgs || rc=$?
	return $rc
}

t32_bits_per_long() {
	#
	# Yes, this is not meant to be perfect.
	#
	case $1 in
		ppc64|x86_64)
			echo -n 64;;
		i*86)
			echo -n 32;;
	esac
}

t32_reload_modules() {
	local node=$1
	local all_removed=false
	local i=0

	[ "$mds1_FSTYPE" == zfs ] && do_rpc_nodes $node "service zed stop"

	while ((i < 20)); do
		echo "Unloading modules on $node: Attempt $i"
		do_rpc_nodes $node $LUSTRE_RMMOD "$mds1_FSTYPE" &&
			all_removed=true
		do_rpc_nodes $node check_mem_leak || return 1
		if $all_removed; then
			do_rpc_nodes $node load_modules
			return 0
		fi
		if [ "$mds1_FSTYPE" == zfs ]; then
			do_rpc_nodes $node "$ZPOOL status -v"
		fi
		sleep 5
		i=$((i + 1))
	done
	echo "Unloading modules on $node: Given up"
	return 1
}

t32_wait_til_devices_gone() {
	local node=$1
	local devices
	local loops
	local i=0

	echo wait for devices to go
	while ((i < 20)); do
		devices=$(do_rpc_nodes $node $LCTL device_list | wc -l)
		loops=$(do_rpc_nodes $node losetup -a | grep -c t32)
		((devices == 0 && loops == 0)) && return 0
		sleep 5
		i=$((i + 1))
	done
	echo "waiting for dev on $node: dev $devices loop $loops given up"
	do_rpc_nodes $node "losetup -a"
	do_rpc_nodes $node "$LCTL device_list"
	return 1
}

t32_verify_quota() {
	local facet=$1
	local fsname=$2
	local mnt=$3
	local qval
	local cmd

	# LU-2435: if the underlying zfs doesn't support userobj_accounting,
	# lustre will estimate the object count usage. This fails quota
	# verification in 32b. The object quota usage should be accurate after
	# zfs-0.7.0 is released.
	[ "$mds1_FSTYPE" == zfs ] && {
		local zfs_version=$(do_facet $facet cat /sys/module/zfs/version)

		[ $(version_code $zfs_version) -lt $(version_code 0.7.0) ] && {
			echo "Skip quota verify for zfs: $zfs_version"
			return 0
		}
	}

	$LFS quota -u $T32_QID -v $mnt

	qval=$($LFS quota -v -u $T32_QID $mnt |
		awk 'BEGIN { num='1' } { if ($1 == "'$mnt'") \
		{ if (NF == 1) { getline } else { num++ } ; print $num;} }' \
		| tr -d "*")
	[ $qval -eq $img_bspace ] || {
		echo "bspace, act:$qval, exp:$img_bspace"
		return 1
	}

	qval=$($LFS quota -v -u $T32_QID $mnt |
		awk 'BEGIN { num='5' } { if ($1 == "'$mnt'") \
		{ if (NF == 1) { getline } else { num++ } ; print $num;} }' \
		| tr -d "*")
	[ $qval -eq $img_ispace ] || {
		echo "ispace, act:$qval, exp:$img_ispace"
		return 1
	}

	qval=$($LFS quota -v -u $T32_QID $mnt |
		awk 'BEGIN { num='3' } { if ($1 == "'$mnt'") \
		{ if (NF == 1) { getline } else { num++ } ; print $num;} }' \
		| tr -d "*")
	[ $qval -eq $img_blimit ] || {
		echo "blimit, act:$qval, exp:$img_blimit"
		return 1
	}

	qval=$($LFS quota -v -u $T32_QID $mnt |
		awk 'BEGIN { num='7' } { if ($1 == "'$mnt'") \
		{ if (NF == 1) { getline } else { num++ } ; print $num;} }' \
		| tr -d "*")
	[ $qval -eq $img_ilimit ] || {
		echo "ilimit, act:$qval, exp:$img_ilimit"
		return 1
	}

	set_persistent_param_and_check $facet \
		"osd-$mds1_FSTYPE.$fsname-MDT0000.quota_slave.enabled" \
		"$fsname.quota.mdt" ug

	set_persistent_param_and_check $facet \
		"osd-$mds1_FSTYPE.$fsname-OST0000.quota_slave.enabled" \
		"$fsname.quota.ost" ug

	chmod 0777 $mnt
	runas -u $T32_QID -g $T32_QID dd if=/dev/zero of=$mnt/t32_qf_new \
		bs=1M count=$((img_blimit / 1024)) oflag=sync && {
		echo "Write succeed, but expect -EDQUOT"
		return 1
	}
	rm -f $mnt/t32_qf_new

	runas -u $T32_QID -g $T32_QID createmany -m $mnt/t32_qf_ \
		$img_ilimit && {
		echo "Create succeed, but expect -EDQUOT"
		return 1
	}
	unlinkmany $mnt/t32_qf_ $img_ilimit

	return 0
}

t32_test() {
	local tarball=$1
	local writeconf=$2
	local dne_upgrade=${dne_upgrade:-"no"}
	local dom_upgrade=${dom_upgrade:-"no"}
	local project_upgrade=${project_upgrade:-"no"}
	local ff_convert=${ff_convert:-"no"}
	local shall_cleanup_mdt=false
	local shall_cleanup_mdt1=false
	local shall_cleanup_ost=false
	local shall_cleanup_lustre=false
	local mdt2_is_available=false
	local node=$(facet_active_host $SINGLEMDS)
	local r="do_node $node"
	local tmp=$TMP/t32
	local img_commit
	local img_kernel
	local img_arch
	local img_bspace
	local img_ispace
	local img_blimit
	local img_ilimit
	local fsname=t32fs
	local nid
	local mopts
	local uuid
	local nrpcs_orig
	local nrpcs
	local list
	local mdt_dev=$tmp/mdt
	local mdt2_dev=$tmp/mdt2
	local ost_dev=$tmp/ost
	local stripe_index
	local stripe_count
	local dir

	combined_mgs_mds || stop_mgs || error "Unable to stop MGS"
	trap 'trap - RETURN; t32_test_cleanup' RETURN

	load_modules
	nid=$($r $LCTL list_nids | head -1)

	mkdir -p $tmp/mnt/lustre || error "mkdir $tmp/mnt/lustre failed"
	$r mkdir -p $tmp/mnt/{mdt,mdt1,ost}
	$r tar xjvf $tarball -S -C $tmp || {
		error_noexit "Unpacking the disk image tarball"
		return 1
	}
	img_commit=$($r cat $tmp/commit)
	img_kernel=$($r cat $tmp/kernel)
	img_arch=$($r cat $tmp/arch)
	img_bspace=$($r cat $tmp/bspace)
	img_ispace=$($r cat $tmp/ispace)

	# older images did not have "blimit" and "ilimit" files
	# use old values for T32_BLIMIT and T32_ILIMIT
	$r test -f $tmp/blimit && img_blimit=$($r cat $tmp/blimit) ||
		img_blimit=20480
	$r test -f $tmp/ilimit && img_ilimit=$($r cat $tmp/ilimit) ||
		img_ilimit=2

	echo "Upgrading from $(basename $tarball), created with:"
	echo "  Commit: $img_commit"
	echo "  Kernel: $img_kernel"
	echo "    Arch: $img_arch"
	echo "OST version: $(lustre_build_version ost1)"

	# The conversion can be made only when both of the following
	# conditions are satisfied:
	# - ost device img version < 2.3.64
	# - ost server version >= 2.5
	[ $(version_code $img_commit) -ge $(version_code 2.3.64) -o \
		"$OST1_VERSION" -lt $(version_code 2.5.0) ] &&
			ff_convert="no"

	! $r test -f $mdt2_dev || mdt2_is_available=true

	if [[ "$mds1_FSTYPE" == zfs ]]; then
		# import pool first
		local poolname
		local poolname_list="t32fs-mdt1 t32fs-ost1"

		! $mdt2_is_available || poolname_list+=" t32fs-mdt2"

		for poolname in $poolname_list; do
			$r "modprobe zfs;
				$ZPOOL list -H $poolname >/dev/null 2>&1 ||
				$ZPOOL import -f -d $tmp $poolname"
		done

		# upgrade zpool to latest supported features, including
		# dnode quota accounting in 0.7.0
		$r "$ZPOOL upgrade -a"

		mdt_dev=t32fs-mdt1/mdt1
		ost_dev=t32fs-ost1/ost1
		! $mdt2_is_available || mdt2_dev=t32fs-mdt2/mdt2
		wait_update_facet $SINGLEMDS "$ZPOOL list |
			awk '/^t32fs-mdt1/ { print \\\$1 }'" "t32fs-mdt1" || {
				error_noexit "import zfs pool failed"
				return 1
			}
	elif [ "$project_upgrade" != "no" ]; then
		! $r tune2fs -O project $mdt_dev &&
			error_noexit "enable project on mdt0 failed" &&
				return 1
		$mdt2_is_available && ! $r tune2fs "-O project" $mdt2_dev &&
			error_noexit "enable project on mdt failed" &&
				return 1
		! $r tune2fs -O project $ost_dev &&
			error_noexit "enable project on mdt failed" &&
				return 1
	fi

	$r $LCTL set_param debug="$PTLDEBUG"

	$r $TUNEFS --dryrun $mdt_dev || {
		$r losetup -a
		error_noexit "tunefs.lustre before mounting the MDT"
		return 1
	}

	if $mdt2_is_available; then
		$r $TUNEFS --dryrun $mdt2_dev || {
			$r losetup -a
			error_noexit "tunefs.lustre before mounting the MDT"
			return 1
		}
	fi

	if [ "$writeconf" ]; then
		mopts=writeconf
		if [ "$mds1_FSTYPE" == ldiskfs ]; then
			mopts="loop,$mopts"
			$r $TUNEFS --quota $mdt_dev || {
				$r losetup -a
				error_noexit "Enable mdt quota feature"
				return 1
			}
			if $mdt2_is_available; then
				$r $TUNEFS --quota $mdt2_dev || {
					$r losetup -a
					error_noexit "Enable mdt quota feature"
					return 1
				}
			fi
		fi
	else
		if [ -n "$($LCTL list_nids | grep -v '\(tcp\|lo\)[[:digit:]]*$')" ]; then
			[[ "$MGS_VERSION" -ge $(version_code 2.3.59) ]] ||
			skip "LU-2200: Cannot run over IB w/o lctl replace_nids "
				"(Need MGS version at least 2.3.59)"

			local osthost=$(facet_active_host ost1)
			local ostnid=$(do_node $osthost $LCTL list_nids | head -1)

			mopts=nosvc
			if [ "$mds1_FSTYPE" == ldiskfs ]; then
				mopts="loop,$mopts"
			fi
			$r $MOUNT_CMD -o $mopts $mdt_dev $tmp/mnt/mdt
			$r $LCTL replace_nids $fsname-OST0000 $ostnid
			$r $LCTL replace_nids $fsname-MDT0000 $nid
			$r $UMOUNT $tmp/mnt/mdt
		fi

		mopts=exclude=$fsname-OST0000
		if [ "$mds1_FSTYPE" == ldiskfs ]; then
			mopts="loop,$mopts"
		fi
	fi

	t32_wait_til_devices_gone $node

	$r $MOUNT_CMD -o $mopts $mdt_dev $tmp/mnt/mdt || {
		$r losetup -a
		error_noexit "Mounting the MDT"
		return 1
	}
	shall_cleanup_mdt=true

	if $mdt2_is_available; then
		mopts=mgsnode=$nid,$mopts
		$r $MOUNT_CMD -o $mopts $mdt2_dev $tmp/mnt/mdt1 || {
			$r losetup -a
			error_noexit "Mounting the MDT"
			return 1
		}

		echo "mount new MDT....$mdt2_dev"
		$r $LCTL set_param -n mdt.${fsname}*.enable_remote_dir=1 ||
			error_noexit "enable remote dir create failed"

		shall_cleanup_mdt1=true
	elif [ "$dne_upgrade" != "no" ]; then
		local fs2mdsdev=$(mdsdevname 1_2)
		local fs2mdsvdev=$(mdsvdevname 1_2)

		echo "mkfs new MDT on ${fs2mdsdev}...."
		if [ "$mds1_FSTYPE" == ldiskfs ]; then
			mkfsoptions="--mkfsoptions=\\\"-J size=8\\\""
		fi

		add $SINGLEMDS $(mds2failover_HOST="" \
			mkfs_opts mds2 $fs2mdsdev $fsname) --reformat \
			$mkfsoptions $fs2mdsdev $fs2mdsvdev > /dev/null || {
			error_noexit "Mkfs new MDT failed"
			return 1
		}

		[[ "$mds1_FSTYPE" != zfs ]] || import_zpool mds1

		$r $TUNEFS --dryrun $fs2mdsdev || {
			error_noexit "tunefs.lustre before mounting the MDT"
			return 1
		}

		echo "mount new MDT....$fs2mdsdev"
		$r $MOUNT_CMD -o $mopts $fs2mdsdev $tmp/mnt/mdt1 || {
			error_noexit "mount mdt1 failed"
			return 1
		}

		$r $LCTL set_param -n mdt.${fsname}*.enable_remote_dir=1 ||
			error_noexit "enable remote dir create failed"

		shall_cleanup_mdt1=true
	fi

	uuid=$($r $LCTL get_param -n mdt.$fsname-MDT0000.uuid) || {
		error_noexit "Getting MDT UUID"
		return 1
	}
	if [ "$uuid" != $fsname-MDT0000_UUID ]; then
		error_noexit "Unexpected MDT UUID: \"$uuid\""
		return 1
	fi

	$r $TUNEFS --dryrun $ost_dev || {
		error_noexit "tunefs.lustre before mounting the OST"
		return 1
	}
	if [ "$writeconf" ]; then
		mopts=mgsnode=$nid,$writeconf
		if [ "$mds1_FSTYPE" == ldiskfs ]; then
			mopts="loop,$mopts"
			$r $TUNEFS --quota $ost_dev || {
				$r losetup -a
				error_noexit "Enable ost quota feature"
				return 1
			}
		fi
	else
		mopts=mgsnode=$nid
		if [ "$mds1_FSTYPE" == ldiskfs ]; then
			mopts="loop,$mopts"
		fi
	fi

	$r $MOUNT_CMD -onomgs -o$mopts $ost_dev $tmp/mnt/ost || {
		error_noexit "Mounting the OST"
		return 1
	}
	shall_cleanup_ost=true

	uuid=$($r $LCTL get_param -n obdfilter.$fsname-OST0000.uuid) || {
		error_noexit "Getting OST UUID"
		return 1
	}
	if [ "$uuid" != $fsname-OST0000_UUID ]; then
		error_noexit "Unexpected OST UUID: \"$uuid\""
		return 1
	fi

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		$r $PERM_CMD osc.$fsname-OST0000*.import=connection=$nid || {
			error_noexit "Setting OST \"failover.node\""
			return 1
		}
		$r $PERM_CMD mdc.$fsname-MDT0000*.import=connection=$nid || {
			error_noexit "Setting MDT \"failover.node\""
			return 1
		}
		$r $PERM_CMD osc.$fsname-OST0000-*.max_dirty_mb=15 || {
			error_noexit "Setting \"max_dirty_mb\""
			return 1
		}
		$r $PERM_CMD mdc.$fsname-MDT0000-*.max_rpcs_in_flight=9 || {
			error_noexit "Setting \"max_rpcs_in_flight\""
			return 1
		}
		$r $PERM_CMD lov.$fsname-MDT0000-*.stripesize=4M || {
			error_noexit "Setting \"lov.stripesize\""
			return 1
		}
		$r $PERM_CMD mdd.$fsname-MDT0000-*.atime_diff=70 || {
			error_noexit "Setting \"mdd.atime_diff\""
			return 1
		}
	else
		$r $PERM_CMD $fsname-OST0000.failover.node=$nid || {
			error_noexit "Setting OST \"failover.node\""
			return 1
		}

		$r $PERM_CMD $fsname-MDT0000.failover.node=$nid || {
			error_noexit "Setting MDT \"failover.node\""
			return 1
		}

		$r $PERM_CMD $fsname-OST0000.osc.max_dirty_mb=15 || {
			error_noexit "Setting \"max_dirty_mb\""
			return 1
		}
		$r $PERM_CMD $fsname-MDT0000.mdc.max_rpcs_in_flight=9 || {
			error_noexit "Setting \"max_rpcs_in_flight\""
			return 1
		}
		$r $PERM_CMD $fsname-MDT0000.lov.stripesize=4M || {
			error_noexit "Setting \"lov.stripesize\""
			return 1
		}
		$r $PERM_CMD $fsname-MDT0000.mdd.atime_diff=70 || {
			error_noexit "Setting \"mdd.atime_diff\""
			return 1
		}
	fi

	$r $LCTL pool_new $fsname.interop || {
		error_noexit "Setting \"interop\""
		return 1
	}

	if [ "$ff_convert" != "no" -a "$ost1_FSTYPE" == ldiskfs ]; then
		$r $LCTL lfsck_start -M $fsname-OST0000 || {
			error_noexit "Start OI scrub on OST0"
			return 1
		}

		# The oi_scrub should be on ost1, but for test_32(),
		# all on the SINGLEMDS.
		wait_update_facet $SINGLEMDS "$LCTL get_param -n \
			osd-ldiskfs.$fsname-OST0000.oi_scrub |
			awk '/^status/ { print \\\$2 }'" "completed" 30 || {
			error_noexit "Failed to get the expected 'completed'"
			return 1
		}

		local UPDATED=$($r $LCTL get_param -n \
				osd-ldiskfs.$fsname-OST0000.oi_scrub |
				awk '/^updated/ { print $2 }')
		[ $UPDATED -ge 1 ] || {
			error_noexit "Only $UPDATED objects have been converted"
			return 1
		}
	fi

	if [ "$dne_upgrade" != "no" ]; then
		if [[ $PERM_CMD == *"set_param -P"* ]]; then
			$r $PERM_CMD mdc.$fsname-MDT0001*.import=connection=$nid || {
				error_noexit "Setting MDT1 \"failover.node\""
				return 1
			}

			$r $PERM_CMD mdc.$fsname-MDT0001-*.max_rpcs_in_flight=9 || {
				error_noexit "Setting MDT1 \"max_rpcs_in_flight\""
				return 1
			}
			$r $PERM_CMD lov.$fsname-MDT0001-*.stripesize=4M || {
				error_noexit "Setting MDT1 \"lov.stripesize\""
				return 1
			}
		else
			$r $PERM_CMD $fsname-MDT0001.failover.node=$nid || {
				error_noexit "Setting MDT1 \"failover.node\""
				return 1
			}
			$r $PERM_CMD $fsname-MDT0001.mdc.max_rpcs_in_flight=9 || {
				error_noexit "Setting MDT1 \"max_rpcs_in_flight\""
				return 1
			}
			$r $PERM_CMD $fsname-MDT0001.lov.stripesize=4M || {
				error_noexit "Setting MDT1 \"lov.stripesize\""
				return 1
			}
		fi
	fi

	if [ "$writeconf" ]; then
		$MOUNT_CMD $nid:/$fsname $tmp/mnt/lustre || {
			error_noexit "Mounting the client"
			return 1
		}

		shall_cleanup_lustre=true
		$r $LCTL set_param debug="$PTLDEBUG"

		# Leave re-enabling this to a separate patch for LU-11558
		# t32_verify_quota $SINGLEMDS $fsname $tmp/mnt/lustre || {
		#	error_noexit "verify quota failed"
		#	return 1
		#}

		if $r test -f $tmp/list; then
			#
			# There is not a Test Framework API to copy files to or
			# from a remote node.
			#
			# LU-2393 - do both sorts on same node to ensure locale
			# is identical
			local list_file=$tmp/list

			if $mdt2_is_available; then
				if [[ -d $tmp/mnt/lustre/striped_dir_old ]] &&
				   $r test -f $tmp/list2; then
					list_file=$tmp/list2
					pushd $tmp/mnt/lustre/striped_dir_old
				else
					pushd $tmp/mnt/lustre/remote_dir
				fi
			else
				pushd $tmp/mnt/lustre
			fi
			$r cat $list_file | sort -k 6 >$tmp/list.orig
			ls -Rni --time-style=+%s | sort -k 6 |
				sed 's/\. / /' >$tmp/list || {
				error_noexit "ls"
				return 1
			}
			popd
			#
			# 32-bit and 64-bit clients use different algorithms to
			# convert FIDs into inode numbers.  Hence, remove the
			# inode numbers from the lists, if the original list was
			# created on an architecture with different number of
			# bits per "long".
			#
			if [ $(t32_bits_per_long $(uname -m)) != \
				$(t32_bits_per_long $img_arch) ]; then
				echo "Different number of bits per \"long\"" \
				     "from the disk image"
				for list in list.orig list; do
					sed -i -e 's/^[0-9]\+[ \t]\+//' \
						  $tmp/$list
				done
			fi
			if ! diff -ub $tmp/list.orig $tmp/list; then
				error_noexit "list verification failed"
				return 1
			fi
		else
			echo "list verification skipped"
		fi

		if [ "$dom_upgrade" != "no" ]; then
			echo "Check DoM file can be created"
			$LFS setstripe -E 1M -L mdt -E EOF $tmp/mnt/lustre/dom || {
				error_noexit "Verify DoM creation"
				return 1
			}
			[ $($LFS getstripe -L $tmp/mnt/lustre/dom) == "mdt" ] || {
				error_noexit "Verify a DoM file"
				return 1
			}
			dd if=/dev/urandom of=$tmp/mnt/lustre/dom bs=4096 \
				count=1 conv=fsync || {
				error_noexit "Cannot write to DoM file"
				return 1
			}
			[ $(stat -c%s $tmp/mnt/lustre/dom) == 4096 ] || {
				error_noexit "DoM: bad size after write"
				return 1
			}
			rm $tmp/mnt/lustre/dom

			set_persistent_param_and_check mds \
			   "lod.*MDT0000*.dom_stripesize" \
			   "$fsname-MDT0000.lod.dom_stripesize" 0 || {
				error_noexit "Changing \"dom_stripesize\""
				return 1
			}
		fi

		if [ "$dne_upgrade" != "no" ]; then
			$LFS mkdir -i 1 -c2 $tmp/mnt/lustre/striped_dir || {
				error_noexit "set striped dir failed"
				return 1
			}

			$LFS setdirstripe -D -c2 $tmp/mnt/lustre/striped_dir

			pushd $tmp/mnt/lustre
			tar -c --exclude=./striped_dir \
				--exclude=./striped_dir_old \
				--exclude=./remote_dir -f - .|
				tar -xvf - -C striped_dir 1>/dev/null || {
				error_noexit "cp to striped dir failed"
				return 1
			}
			popd
		fi

		# If it is upgrade from DNE (2.5), then rename the remote dir,
		# which is created in 2.5 to striped dir.
		if $mdt2_is_available && [[ "$dne_upgrade" != "no" ]]; then
			stripe_index=$($LFS getdirstripe -i	\
				       $tmp/mnt/lustre/remote_dir)

			[[ $stripe_index -eq 1 ]] || {
				error_noexit "get index \"$stripe_index\"" \
					     "from remote dir failed"
				return 1
			}
			mv $tmp/mnt/lustre/remote_dir	\
				$tmp/mnt/lustre/striped_dir/ || {
				error_noexit "mv remote dir failed"
				return 1
			}
		fi

		# If it is upgraded from DNE (2.7), then move the striped dir
		# which was created in 2.7 to the new striped dir.
		if $mdt2_is_available && [[ "$dne_upgrade" != "no" ]] &&
			[[ -d $tmp/mnt/lustre/striped_dir_old ]]; then
			stripe_count=$($LFS getdirstripe -c	\
				       $tmp/mnt/lustre/striped_dir_old)
			[[ $stripe_count -eq 2 ]] || {
				error_noexit "get count $stripe_count" \
					     "from striped dir failed"
				return 1
			}
			mv $tmp/mnt/lustre/striped_dir_old	\
				$tmp/mnt/lustre/striped_dir/ || {
				error_noexit "mv striped dir failed"
				return 1
			}
		fi

		sync; sleep 5; sync
		$r $LCTL set_param -n osd*.*.force_sync=1
		dd if=/dev/zero of=$tmp/mnt/lustre/tmp_file bs=10k count=10 || {
			error_noexit "dd failed"
			return 1
		}
		rm -rf $tmp/mnt/lustre/tmp_file || {
			error_noexit "rm failed"
			return 1
		}

		if $r test -f $tmp/sha1sums; then
			# LU-2393 - do both sorts on same node to ensure locale
			# is identical
			$r cat $tmp/sha1sums | sort -k 2 >$tmp/sha1sums.orig
			if [ "$dne_upgrade" != "no" ]; then
				pushd $tmp/mnt/lustre/striped_dir
			else
				pushd $tmp/mnt/lustre
			fi

			find ! -path "*remote_dir*" ! -path "*striped_dir*" \
				! -name .lustre -type f -exec sha1sum {} \; |
				sort -k 2 >$tmp/sha1sums || {
				popd
				error_noexit "sha1sum"
				return 1
			}
			popd
			if ! diff -ub $tmp/sha1sums.orig $tmp/sha1sums; then
				error_noexit "sha1sum verification failed"
				return 1
			fi

			# if upgrade from DNE(2.5), then check remote directory
			# if upgrade from DNE(2.7), then check striped directory
			if $mdt2_is_available &&
			   [[ "$dne_upgrade" != "no" ]]; then
				local new_dir="$tmp/mnt/lustre/striped_dir"
				local striped_dir_old="$new_dir/striped_dir_old"

				local dir_list="$new_dir/remote_dir"
				[[ ! -d $triped_dir_old ]] ||
					dir_list+=" $striped_dir_old"

				for dir in $dir_list; do
					pushd $dir
					find ! -name .lustre -type f	\
						-exec sha1sum {} \; |
						sort -k 2 >$tmp/sha1sums || {
							popd
							error_noexit "sha1sum"
							return 1
						}
					popd
					if ! diff -ub $tmp/sha1sums.orig \
						$tmp/sha1sums; then
						error_noexit "sha1sum $dir" \
							     "failed"
						return 1
					fi
				done
			fi
		else
			echo "sha1sum verification skipped"
		fi

		if [ "$dne_upgrade" != "no" ]; then
			rm -rf $tmp/mnt/lustre/striped_dir || {
				error_noexit "remove remote dir failed"
				return 1
			}
		fi

		# migrate files/dirs to remote MDT, then move them back
		if [ "$MDS1_VERSION" -ge $(version_code 2.7.50) -a \
		     $dne_upgrade != "no" ]; then
			$r $LCTL set_param -n	\
				mdt.${fsname}*.enable_remote_dir=1 2>/dev/null

			echo "test migration"
			pushd $tmp/mnt/lustre
			for dir in $(find ! -name .lustre ! -name . -type d); do
				mdt_index=$($LFS getdirstripe -i $dir)
				stripe_cnt=$($LFS getdirstripe -c $dir)
				if [ $mdt_index = 0 -a $stripe_cnt -le 1 ]; then
					$LFS migrate -m 1 $dir || {
					popd
					error_noexit "migrate MDT1 failed"
					return 1
				}
				fi
			done

			for dir in $(find ! -name . ! -name .lustre -type d); do
				mdt_index=$($LFS getdirstripe -i $dir)
				stripe_cnt=$($LFS getdirstripe -c $dir)
				if [ $mdt_index = 1 -a $stripe_cnt -le 1 ]; then
					$LFS migrate -m 0 $dir || {
					popd
					error_noexit "migrate MDT0 failed"
					return 1
				}
				fi
			done
			popd
		fi

		#
		# When adding new data verification tests, please check for
		# the presence of the required reference files first, like
		# the "sha1sums" and "list" tests above, to avoid the need to
		# regenerate every image for each test addition.
		#

		nrpcs_orig=$($LCTL get_param \
				-n mdc.*MDT0000*.max_rpcs_in_flight) || {
			error_noexit "Getting \"max_rpcs_in_flight\""
			return 1
		}
		nrpcs=$((nrpcs_orig + 5))

		set_persistent_param_and_check client \
		   "mdc.$fsname-MDT0000*.max_rpcs_in_flight" \
		   "$fsname-MDT0000.mdc.max_rpcs_in_flight" $nrpcs || {
			error_noexit "Changing \"max_rpcs_in_flight\""
			return 1
		}

		umount $tmp/mnt/lustre || {
			error_noexit "Unmounting the client"
			return 1
		}
		shall_cleanup_lustre=false
	else
		$MOUNT_CMD $nid:/$fsname $tmp/mnt/lustre || {
			error_noexit "Mounting the client"
			return 1
		}

		if [ "$mds1_FSTYPE" == ldiskfs -a \
		    "$project_upgrade" != "no" ]; then
			! $LFS project -d -p 1 $tmp/mnt/lustre/* &&
				error_noexit "set project failed" &&
					return 1
		fi

		[[ $(do_facet mds1 pgrep orph_.*-MDD | wc -l) == 0 ]] ||
			error "MDD orphan cleanup thread not quit"

		umount $tmp/mnt/lustre || {
			error_noexit "Unmounting the client"
			return 1
		}

		if [[ "$dne_upgrade" != "no" ]] || $mdt2_is_available; then
			$r $UMOUNT $tmp/mnt/mdt1 || {
				error_noexit "Unmounting the MDT2"
				return 1
			}
			if [[ "$mds1_FSTYPE" == zfs ]]; then
			    $r "$ZPOOL export t32fs-mdt2"
			fi
			shall_cleanup_mdt1=false
		fi

		$r $UMOUNT $tmp/mnt/mdt || {
			error_noexit "Unmounting the MDT"
			return 1
		}
		if [[ "$mds1_FSTYPE" == zfs ]]; then
		    $r "$ZPOOL export t32fs-mdt1"
		fi
		shall_cleanup_mdt=false

		$r $UMOUNT $tmp/mnt/ost || {
			error_noexit "Unmounting the OST"
			return 1
		}
		if [[ "$mds1_FSTYPE" == zfs ]]; then
		    $r "$ZPOOL export t32fs-ost1"
		fi
		shall_cleanup_ost=false

		t32_reload_modules $node || {
			error_noexit "Reloading modules"
			return 1
		}

		if [[ "$mds1_FSTYPE" == zfs ]]; then
			local poolname=t32fs-mdt1
			$r "modprobe zfs;
			    $ZPOOL list -H $poolname >/dev/null 2>&1 ||
				$ZPOOL import -f -d $tmp $poolname"

			# upgrade zpool to latest supported features,
			# including dnode quota accounting in 0.7.0
			$r "$ZPOOL upgrade $poolname"
		fi

		# mount a second time to make sure we didnt leave upgrade flag on
		$r $TUNEFS --dryrun $mdt_dev || {
			$r losetup -a
			error_noexit "tunefs.lustre before remounting the MDT"
			return 1
		}

		mopts=exclude=$fsname-OST0000
		if [ "$mds1_FSTYPE" == ldiskfs ]; then
			mopts="loop,$mopts"
		fi
		$r $MOUNT_CMD -o $mopts $mdt_dev $tmp/mnt/mdt || {
			error_noexit "Remounting the MDT"
			return 1
		}
		shall_cleanup_mdt=true
	fi
}

test_32a() {
	local tarballs
	local tarball
	local rc=0

	t32_check
	for tarball in $tarballs; do
		banner "testing $tarball upgrade"
		t32_test $tarball || let "rc += $?"
	done
	return $rc
}
run_test 32a "Upgrade (not live)"

test_32b() {
	local tarballs
	local tarball
	local rc=0

	t32_check
	for tarball in $tarballs; do
		banner "testing $tarball upgrade with writeconf"
		t32_test $tarball writeconf || let "rc += $?"
	done
	return $rc
}
run_test 32b "Upgrade with writeconf"

test_32c() {
	local tarballs
	local tarball
	local rc=0

	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	t32_check
	for tarball in $tarballs; do
		# Do not support 1_8 and 2_1 direct upgrade to DNE2 anymore */
		[[ "$tarball" =~ "1_8" ]] && echo "skip $tarball" && continue
		[[ "$tarball" =~ "2_1" ]] && echo "skip $tarball" && continue
		banner "testing $tarball upgrade with DNE"
		load_modules
		dne_upgrade=yes t32_test $tarball writeconf || rc=$?
	done
	return $rc
}
run_test 32c "dne upgrade test"

test_32d() {
	local tarballs
	local tarball
	local rc=0

	t32_check
	for tarball in $tarballs; do
		banner "testing $tarball upgrade with ff convert and project upgrade"
		project_upgrade="no"
		[[ "$MDS1_VERSION" -ge $(version_code 2.13.54) ]] &&
			[[ "$tarball" =~ "disk2_4-ldiskfs" ]] &&
				project_upgrade="yes"
		project_upgrade=$project_upgrade ff_convert=yes t32_test \
			$tarball || rc=$?
	done
	return $rc
}
run_test 32d "convert ff and project quota upgrade test"

test_32e() {
	[[ "$MDS1_VERSION" -ge $(version_code 2.10.56) ]] ||
		skip "Need MDS version at least 2.10.56"

	local tarballs
	local tarball
	local rc=0

	t32_check
	for tarball in $tarballs; do
		[[ "$tarball" =~ "2_9" ]] || continue
		#load_modules
		banner "testing $tarball upgrade with DoM"
		dom_upgrade=yes t32_test $tarball writeconf || let "rc += $?"
	done
	return $rc
}
run_test 32e "dom upgrade test"

test_33a() { # bug 12333, was test_33
	local FSNAME2=test-123
	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})
	local mkfsoptions

	[ -n "$ost1_HOST" ] && fs2ost_HOST=$ost1_HOST

	if [ -z "$fs2ost_DEV" -o -z "$fs2mds_DEV" ]; then
		local dev=${SINGLEMDS}_dev
		local MDSDEV=${!dev}
		is_blkdev $SINGLEMDS $MDSDEV &&
			skip_env "mixed loopback and real device not working"
	fi

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2ostdev=$(ostdevname 1_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)
	local fs2ostvdev=$(ostvdevname 1_2)

	if [ "$mds1_FSTYPE" == ldiskfs ]; then
		mkfsoptions="--mkfsoptions=\\\"-J size=8\\\"" # See bug 17931.
	fi

	if combined_mgs_mds; then
		local mgs_flag="--mgs"
	fi

	add fs2mds $(mkfs_opts mds1 ${fs2mdsdev}) --fsname=${FSNAME2} \
		--reformat $mgs_flag $mkfsoptions $fs2mdsdev $fs2mdsvdev ||
		exit 10
	add fs2ost $(mkfs_opts ost1 ${fs2ostdev}) --mgsnode=$MGSNID \
		--fsname=${FSNAME2} --index=8191 --reformat $fs2ostdev \
		$fs2ostvdev || exit 10

	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS && trap cleanup_fs2 EXIT INT
	start fs2ost $fs2ostdev $OST_MOUNT_OPTS

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		do_facet mgs "$PERM_CMD timeout=200" ||
			error "$PERM_CMD timeout=200 failed"
	else
		do_facet mgs "$PERM_CMD $FSNAME2.sys.timeout=200" ||
			error "$PERM_CMD $FSNAME2.sys.timeout=200 failed"
	fi
	mkdir -p $MOUNT2 || error "mkdir $MOUNT2 failed"
	$MOUNT_CMD $MGSNID:/${FSNAME2} $MOUNT2 || error "$MOUNT_CMD failed"
	echo "ok."

	cp /etc/hosts $MOUNT2/ || error "copy /etc/hosts $MOUNT2/ failed"
	$LFS getstripe $MOUNT2/hosts ||
		error "$LFS getstripe $MOUNT2/hosts failed"

	umount $MOUNT2
	stop fs2ost -f
	stop fs2mds -f
	cleanup_nocli || error "cleanup_nocli failed with $?"
}
run_test 33a "Mount ost with a large index number"

test_33b() {	# was test_34
        setup

        do_facet client dd if=/dev/zero of=$MOUNT/24 bs=1024k count=1
        # Drop lock cancelation reply during umount
	#define OBD_FAIL_LDLM_CANCEL_NET			0x304
	do_facet client $LCTL set_param fail_loc=0x80000304
	#lctl set_param debug=-1
	umount_client $MOUNT
	cleanup || error "cleanup failed with $?"
}
run_test 33b "Drop cancel during umount"

test_34a() {
        setup
	do_facet client "sh runmultiop_bg_pause $DIR/file O_c"
	manual_umount_client
	rc=$?
	do_facet client killall -USR1 multiop
	if [ $rc -eq 0 ]; then
		error "umount not fail!"
	fi
	sleep 1
	cleanup || error "cleanup failed with rc $?"
}
run_test 34a "umount with opened file should be fail"

test_34b() {
	setup
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"
	stop_mds || error "Unable to stop MDS"

	manual_umount_client --force || error "mtab after failed umount with $?"

	cleanup || error "cleanup failed with $?"
}
run_test 34b "force umount with failed mds should be normal"

test_34c() {
	setup
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"
	stop_ost || error "Unable to stop OST1"

	manual_umount_client --force || error "mtab after failed umount with $?"

	cleanup || error "cleanup failed with $?"
}
run_test 34c "force umount with failed ost should be normal"

test_35a() { # bug 12459
	setup

	DBG_SAVE="`$LCTL get_param -n debug`"
	$LCTL set_param debug="ha"

	log "Set up a fake failnode for the MDS"
	FAKENID="127.0.0.2"
	local device=$(do_facet $SINGLEMDS "$LCTL get_param -n devices" |
		awk '($3 ~ "mdt" && $4 ~ "MDT") { print $4 }' | head -1)

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		do_facet mgs "$PERM_CMD \
			      mdc.*${device}*.import=connection=$(h2nettype $FAKENID)" ||
			error "Setting mdc.*${device}*.import=connection=\
			       $(h2nettype $FAKENID) failed."
	else
		do_facet mgs "$PERM_CMD \
			      ${device}.failover.node=$(h2nettype $FAKENID)" ||
			error "Setting ${device}.failover.node=\
			       $(h2nettype $FAKENID) failed."
	fi
	log "Wait for RECONNECT_INTERVAL seconds (10s)"
	sleep 10

	MSG="conf-sanity.sh test_35a `date +%F%kh%Mm%Ss`"
	$LCTL clear
	log "$MSG"
	log "Stopping the MDT: $device"
	stop_mdt 1 || error "MDT0 stop fail"

	df $MOUNT > /dev/null 2>&1 &
	DFPID=$!
	log "Restarting the MDT: $device"
	start_mdt 1 || error "MDT0 start fail"
	log "Wait for df ($DFPID) ... "
	wait $DFPID
	log "done"
	$LCTL set_param debug="$DBG_SAVE"

	# retrieve from the log the first server that the client tried to
	# contact after the connection loss
	$LCTL dk $TMP/lustre-log-$TESTNAME.log
	NEXTCONN=`awk "/${MSG}/ {start = 1;}
		       /import_select_connection.*$device-mdc.* using connection/ {
				if (start) {
					if (\\\$NF ~ /$FAKENID/)
						print \\\$NF;
					else
						print 0;
					exit;
				}
		       }" $TMP/lustre-log-$TESTNAME.log`
	[ "$NEXTCONN" != "0" ] &&
		error "Tried to connect to ${NEXTCONN} not last active server"
	cleanup || error "cleanup failed with $?"
	# remove nid settings
	writeconf_or_reformat
}
run_test 35a "Reconnect to the last active server first"

test_35b() { # bug 18674
	remote_mds || skip "local MDS"
	setup

	debugsave
	$LCTL set_param debug="ha"
	$LCTL clear
	MSG="conf-sanity.sh test_35b `date +%F%kh%Mm%Ss`"
	log "$MSG"

	log "Set up a fake failnode for the MDS"
	FAKENID="127.0.0.2"
	local device=$(do_facet $SINGLEMDS "$LCTL get_param -n devices" |
		awk '($3 ~ "mdt" && $4 ~ "MDT") { print $4 }' | head -1)

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		do_facet mgs "$PERM_CMD \
			      mdc.*${device}*.import=connection=$(h2nettype $FAKENID)" ||
			error "Set mdc.*${device}*.import=connection=\
			       $(h2nettype $FAKENID) failed"
	else
		do_facet mgs "$PERM_CMD \
			      ${device}.failover.node=$(h2nettype $FAKENID)" ||
			error "Set ${device}.failover.node=\
			       $(h2nettype $FAKENID) failed"
	fi

	local at_max_saved=0
	# adaptive timeouts may prevent seeing the issue
	if at_is_enabled; then
		at_max_saved=$(at_max_get mds)
		at_max_set 0 mds client
	fi

	mkdir $MOUNT/$tdir || error "mkdir $MOUNT/$tdir failed"

	log "Injecting EBUSY on MDS"
	# Setting OBD_FAIL_MDS_RESEND=0x136
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x80000136" ||
		error "unable to set param fail_loc=0x80000136"

	$LCTL set_param mdc.${FSNAME}*.stats=clear

	log "Creating a test file and stat it"
	touch $MOUNT/$tdir/$tfile || error "touch $MOUNT/$tdir/$tfile failed"
	stat $MOUNT/$tdir/$tfile

	log "Stop injecting EBUSY on MDS"
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0" ||
		error "unable to set param fail_loc=0"
	rm -f $MOUNT/$tdir/$tfile || error "remove $MOUNT/$tdir/$tfile failed"

	log "done"
	# restore adaptive timeout
	[ $at_max_saved -ne 0 ] && at_max_set $at_max_saved mds client

	$LCTL dk $TMP/lustre-log-$TESTNAME.log

	CONNCNT=$($LCTL get_param mdc.${FSNAME}*.stats |
		  awk '/mds_connect/{print $2}')

	# retrieve from the log if the client has ever tried to
	# contact the fake server after the loss of connection
	FAILCONN=`awk "BEGIN {ret = 0;}
		       /import_select_connection.*${FSNAME}-MDT0000-mdc.* using connection/ {
				ret = 1;
				if (\\\$NF ~ /$FAKENID/) {
					ret = 2;
					exit;
				}
		       }
		       END {print ret}" $TMP/lustre-log-$TESTNAME.log`

	[ "$FAILCONN" == "0" ] &&
		error "The client reconnection has not been triggered"
	[ "$FAILCONN" == "2" ] &&
		error "Primary server busy, client reconnect to failover failed"

	# LU-290
	# When OBD_FAIL_MDS_RESEND is hit, we sleep for 2 * obd_timeout
	# Reconnects are supposed to be rate limited to one every 5s
	[ $CONNCNT -gt $((2 * $TIMEOUT / 5 + 1)) ] &&
		error "Too many reconnects $CONNCNT"

	cleanup || error "cleanup failed with $?"
	# remove nid settings
	writeconf_or_reformat
}
run_test 35b "Continue reconnection retries, if the active server is busy"

test_36() { # 12743
	[ $OSTCOUNT -lt 2 ] && skip_env "needs >= 2 OSTs"

	[ "$ost_HOST" = "`hostname`" -o "$ost1_HOST" = "`hostname`" ] ||
		skip "remote OST"

	local rc=0
	local FSNAME2=test1234
	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})

	[ -n "$ost1_HOST" ] && fs2ost_HOST=$ost1_HOST && fs3ost_HOST=$ost1_HOST

	if [ -z "$fs2ost_DEV" -o -z "$fs2mds_DEV" -o -z "$fs3ost_DEV" ]; then
		is_blkdev $SINGLEMDS $MDSDEV &&
			skip_env "mixed loopback and real device not working"
	fi

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2ostdev=$(ostdevname 1_2)
	local fs3ostdev=$(ostdevname 2_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)
	local fs2ostvdev=$(ostvdevname 1_2)
	local fs3ostvdev=$(ostvdevname 2_2)

	load_modules
	add fs2mds $(mkfs_opts mds1 ${fs2mdsdev}) --mgs --fsname=${FSNAME2} \
		--reformat $fs2mdsdev $fs2mdsvdev || exit 10
	# XXX after we support non 4K disk blocksize in ldiskfs, specify a
	#     different one than the default value here.
	add fs2ost $(mkfs_opts ost1 ${fs2ostdev}) --mgsnode=$MGSNID \
		--fsname=${FSNAME2} --reformat $fs2ostdev $fs2ostvdev || exit 10
	add fs3ost $(mkfs_opts ost2 ${fs3ostdev}) --mgsnode=$MGSNID \
		--fsname=${FSNAME2} --reformat $fs3ostdev $fs3ostvdev || exit 10

	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS
	start fs2ost $fs2ostdev $OST_MOUNT_OPTS
	start fs3ost $fs3ostdev $OST_MOUNT_OPTS
	mkdir -p $MOUNT2 || error "mkdir $MOUNT2 failed"
	$MOUNT_CMD $MGSNID:/${FSNAME2} $MOUNT2 || error "$MOUNT_CMD failed"

	sleep 5 # until 11778 fixed

	dd if=/dev/zero of=$MOUNT2/$tfile bs=1M count=7 || error "dd failed"

	BKTOTAL=$($LCTL get_param -n obdfilter.*.kbytestotal |
		  awk 'BEGIN{total=0}; {total+=$1}; END{print total}')
	BKFREE=$($LCTL get_param -n obdfilter.*.kbytesfree |
		 awk 'BEGIN{free=0}; {free+=$1}; END{print free}')
	BKAVAIL=$($LCTL get_param -n obdfilter.*.kbytesavail |
		  awk 'BEGIN{avail=0}; {avail+=$1}; END{print avail}')
	STRING=$(df -P $MOUNT2 | tail -n 1 | awk '{print $2","$3","$4}')
	DFTOTAL=$(echo $STRING | cut -d, -f1)
	DFUSED=$(echo $STRING  | cut -d, -f2)
	DFAVAIL=$(echo $STRING | cut -d, -f3)
	DFFREE=$(($DFTOTAL - $DFUSED))

        ALLOWANCE=$((64 * $OSTCOUNT))

        if [ $DFTOTAL -lt $(($BKTOTAL - $ALLOWANCE)) ] ||
           [ $DFTOTAL -gt $(($BKTOTAL + $ALLOWANCE)) ] ; then
                echo "**** FAIL: df total($DFTOTAL) mismatch OST total($BKTOTAL)"
                rc=1
        fi
        if [ $DFFREE -lt $(($BKFREE - $ALLOWANCE)) ] ||
           [ $DFFREE -gt $(($BKFREE + $ALLOWANCE)) ] ; then
                echo "**** FAIL: df free($DFFREE) mismatch OST free($BKFREE)"
                rc=2
        fi
        if [ $DFAVAIL -lt $(($BKAVAIL - $ALLOWANCE)) ] ||
           [ $DFAVAIL -gt $(($BKAVAIL + $ALLOWANCE)) ] ; then
                echo "**** FAIL: df avail($DFAVAIL) mismatch OST avail($BKAVAIL)"
                rc=3
       fi

	$UMOUNT $MOUNT2
	stop fs3ost -f || error "unable to stop OST3"
	stop fs2ost -f || error "unable to stop OST2"
	stop fs2mds -f || error "unable to stop second MDS"
	unload_modules_conf || error "unable unload modules"
	return $rc
}
run_test 36 "df report consistency on OSTs with different block size"

test_37() {
	local mntpt=$(facet_mntpt $SINGLEMDS)
	local mdsdev=$(mdsdevname ${SINGLEMDS//mds/})
	local mdsdev_sym="$TMP/sym_mdt.img"
	local opts=$MDS_MOUNT_OPTS
	local rc=0

	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi

	echo "MDS :     $mdsdev"
	echo "SYMLINK : $mdsdev_sym"
	do_facet $SINGLEMDS rm -f $mdsdev_sym

	do_facet $SINGLEMDS ln -s $mdsdev $mdsdev_sym

	echo "mount symlink device - $mdsdev_sym"

	if ! do_facet $SINGLEMDS test -b $mdsdev; then
		opts=$(csa_add "$opts" -o loop)
	fi

	load_modules
	mount_op=$(do_facet $SINGLEMDS mount -v -t lustre $opts \
		$mdsdev_sym $mntpt 2>&1)
	rc=${PIPESTATUS[0]}

	echo mount_op=$mount_op

	do_facet $SINGLEMDS "$UMOUNT $mntpt && rm -f $mdsdev_sym"

	if $(echo $mount_op | grep -q "unable to set tunable"); then
		error "set tunables failed for symlink device"
	fi

	[ $rc -eq 0 ] || error "mount symlink $mdsdev_sym failed! rc=$rc"
}
run_test 37 "verify set tunables works for symlink device"

test_38() { # bug 14222
	local mntpt=$(facet_mntpt $SINGLEMDS)

	setup
	# like runtests
	local COUNT=10
	local SRC="/etc /bin"
	local FILES=$(find $SRC -type f -mtime +1 | head -n $COUNT)
	log "copying $(echo $FILES | wc -w) files to $DIR/$tdir"
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	tar cf - $FILES | tar xf - -C $DIR/$tdir ||
		error "copying $SRC to $DIR/$tdir"
	sync
	umount_client $MOUNT || error "umount_client $MOUNT failed"
	do_facet $SINGLEMDS "$LCTL get_param osp.*.prealloc_next_id"
	stop_mds || error "Unable to stop MDS"
	log "delete lov_objid file on MDS"

	mount_fstype $SINGLEMDS || error "mount MDS failed (1)"

	do_facet $SINGLEMDS "od -Ax -td8 $mntpt/lov_objid; rm $mntpt/lov_objid"

	unmount_fstype $SINGLEMDS || error "umount failed (1)"

	# check create in mds_lov_connect
	start_mds || error "unable to start MDS"
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	for f in $FILES; do
		[ $V ] && log "verifying $DIR/$tdir/$f"
		diff -q $f $DIR/$tdir/$f || ERROR=y
	done
	do_facet $SINGLEMDS "$LCTL get_param osp.*.prealloc_next_id"
	if [ "$ERROR" = "y" ]; then
		# check it's updates in sync
		umount_client $MOUNT
		stop_mds
		mount_fstype $SIGNLEMDS
		do_facet $SINGLEMDS "od -Ax -td8 $mntpt/lov_objid"
		unmount_fstype $SINGLEMDS
		error "old and new files are different after connect" || true
	fi
	touch $DIR/$tdir/f2 || error "f2 file create failed"

	# check it's updates in sync
	umount_client $MOUNT || error "second umount_client $MOUNT failed"
	stop_mds

	mount_fstype $SINGLEMDS || error "mount MDS failed (3)"

	do_facet $SINGLEMDS "od -Ax -td8 $mntpt/lov_objid"
	do_facet $SINGLEMDS dd if=/dev/zero of=$mntpt/lov_objid.clear count=8

	unmount_fstype $SINGLEMDS || error "umount failed (3)"

	start_mds || error "unable to start MDS"
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	for f in $FILES; do
		[ $V ] && log "verifying $DIR/$tdir/$f"
		diff -q $f $DIR/$tdir/$f || ERROR=y
	done
	touch $DIR/$tdir/f3 || error "f3 file create failed"
	do_facet $SINGLEMDS "$LCTL get_param osp.*.prealloc_next_id"
	umount_client $MOUNT || error "third umount_client $MOUNT failed"
	stop_mds
	mount_fstype $SINGLEMDS || error "mount MDS failed (4)"
	do_facet $SINGLEMDS "od -Ax -td8 $mntpt/lov_objid"
	unmount_fstype $SINGLEMDS || error "umount failed (4)"

	[ "$ERROR" = "y" ] &&
		error "old and new files are different after sync" || true

	log "files compared the same"
	cleanup || error "cleanup failed with $?"
}
run_test 38 "MDS recreates missing lov_objid file from OST data"

test_39() {
	PTLDEBUG=+malloc
	setup
	cleanup || error "cleanup failed with $?"
	perl $SRCDIR/leak_finder.pl $TMP/debug 2>&1 | egrep '*** Leak:' &&
		error "memory leak detected" || true
}
run_test 39 "leak_finder recognizes both LUSTRE and LNET malloc messages"

test_40() { # bug 15759
	start_ost || error "Unable to start OST1"
	#define OBD_FAIL_TGT_TOOMANY_THREADS     0x706
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x80000706"
	start_mds
	cleanup || error "cleanup failed with rc $?"
}
run_test 40 "race during service thread startup"

test_41a() { #bug 14134
	if [ "$mds1_FSTYPE" == ldiskfs ] &&
	   ! do_facet $SINGLEMDS test -b $(mdsdevname 1); then
		skip "Loop devices does not work with nosvc option"
	fi

	combined_mgs_mds || skip "needs combined MGT and MDT device"

	start_mdt 1 -o nosvc -n
	if [ $MDSCOUNT -ge 2 ]; then
		for num in $(seq 2 $MDSCOUNT); do
			start_mdt $num || return
		done
	fi
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS
	start_mdt 1 -o nomgs,force
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	sleep 5

	echo "blah blah" > $MOUNT/$tfile
	cat $MOUNT/$tfile

	umount_client $MOUNT || error "umount_client $MOUNT failed"
	stop ost1 -f || error "unable to stop OST1"
	stop_mds || error "Unable to stop MDS"
	stop_mds || error "Unable to stop MDS on second try"
}
run_test 41a "mount mds with --nosvc and --nomgs"

test_41b() {
	if [ "$mds1_FSTYPE" == ldiskfs ] &&
	   ! do_facet $SINGLEMDS test -b $(mdsdevname 1); then
		skip "Loop devices does not work with nosvc option"
	fi

	! combined_mgs_mds && skip "needs combined mgs device"

	stopall
	reformat
	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})

	start_mdt 1 -o nosvc -n
	if [ $MDSCOUNT -ge 2 ]; then
		for num in $(seq 2 $MDSCOUNT); do
			start_mdt $num || return
		done
	fi
	start_ost || error "Unable to start OST1"
	start_mdt 1 -o nomgs,force
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	sleep 5

	echo "blah blah" > $MOUNT/$tfile
	cat $MOUNT/$tfile || error "cat $MOUNT/$tfile failed"

	umount_client $MOUNT -f || error "umount_client $MOUNT failed"
	stop_ost || error "Unable to stop OST1"
	stop_mds || error "Unable to stop MDS"
	stop_mds || error "Unable to stop MDS on second try"
}
run_test 41b "mount mds with --nosvc and --nomgs on first mount"

test_41c() {
	local oss_list=$(comma_list $(osts_nodes))

	[[ "$MDS1_VERSION" -ge $(version_code 2.6.52) ]] ||
	[[ "$MDS1_VERSION" -ge $(version_code 2.5.26) &&
	   "$MDS1_VERSION" -lt $(version_code 2.5.50) ]] ||
	[[ "$MDS1_VERSION" -ge $(version_code 2.5.4) &&
	   "$MDS1_VERSION" -lt $(version_code 2.5.11) ]] ||
		skip "Need MDS version 2.5.4+ or 2.5.26+ or 2.6.52+"

	# ensure mds1 ost1 have been created even if running sub-test standalone
	cleanup
	setup
	cleanup || error "cleanup failed"

	# using directly mount command instead of start() function to avoid
	# any side effect of // with others/externals tools/features
	# ("zpool import", ...)

	# MDT concurrent start

	LOAD_MODULES_REMOTE=true load_modules
	do_facet $SINGLEMDS "lsmod | grep -q libcfs" ||
		error "MDT concurrent start: libcfs module not loaded"

	local mds1dev=$(mdsdevname 1)
	local mds1mnt=$(facet_mntpt mds1)
	local mds1opts=$MDS_MOUNT_OPTS

	if [ "$mds1_FSTYPE" == ldiskfs ] &&
	   ! do_facet mds1 test -b $mds1dev; then
		mds1opts=$(csa_add "$mds1opts" -o loop)
	fi
	if [[ "$mds1_FSTYPE" == zfs ]]; then
		import_zpool mds1 || return ${PIPESTATUS[0]}
	fi

	#define OBD_FAIL_TGT_MOUNT_RACE 0x716
	do_facet mds1 "$LCTL set_param fail_loc=0x80000716"

	do_facet mds1 mount -t lustre $mds1dev $mds1mnt $mds1opts &
	local pid=$!

	do_facet mds1 mount -t lustre $mds1dev $mds1mnt $mds1opts
	local rc2=$?
	wait $pid
	local rc=$?
	do_facet mds1 "$LCTL set_param fail_loc=0x0"
	if [ $rc -eq 0 ] && [ $rc2 -ne 0 ]; then
		echo "1st MDT start succeed"
		echo "2nd MDT start failed with $rc2"
	elif [ $rc2 -eq 0 ] && [ $rc -ne 0 ]; then
		echo "1st MDT start failed with $rc"
		echo "2nd MDT start succeed"
	else
		stop mds1 -f
		error "unexpected concurrent MDT mounts result, rc=$rc rc2=$rc2"
	fi

	if [ $MDSCOUNT -ge 2 ]; then
		for num in $(seq 2 $MDSCOUNT); do
			start_mdt $num || return
		done
	fi

	# OST concurrent start

	do_rpc_nodes $oss_list "lsmod | grep -q libcfs" ||
		error "OST concurrent start: libcfs module not loaded"

	local ost1dev=$(ostdevname 1)
	local ost1mnt=$(facet_mntpt ost1)
	local ost1opts=$OST_MOUNT_OPTS

	if [ "$ost1_FSTYPE" == ldiskfs ] &&
	   ! do_facet ost1 test -b $ost1dev; then
		ost1opts=$(csa_add "$ost1opts" -o loop)
	fi
	if [[ "$ost1_FSTYPE" == zfs ]]; then
		import_zpool ost1 || return ${PIPESTATUS[0]}
	fi

	#define OBD_FAIL_TGT_MOUNT_RACE 0x716
	do_facet ost1 "$LCTL set_param fail_loc=0x80000716"

	do_facet ost1 mount -t lustre $ost1dev $ost1mnt $ost1opts &
	pid=$!

	do_facet ost1 mount -t lustre $ost1dev $ost1mnt $ost1opts
	rc2=$?
	wait $pid
	rc=$?
	do_facet ost1 "$LCTL set_param fail_loc=0x0"
	if [ $rc -eq 0 ] && [ $rc2 -ne 0 ]; then
		echo "1st OST start succeed"
		echo "2nd OST start failed with $rc2"
	elif [ $rc2 -eq 0 ] && [ $rc -ne 0 ]; then
		echo "1st OST start failed with $rc"
		echo "2nd OST start succeed"
	else
		stop_mds -f
		stop ost1 -f
		error "unexpected concurrent OST mounts result, rc=$rc rc2=$rc2"
	fi
	# cleanup
	stop_mds
	stop ost1 -f

	# verify everything ok
	start_mds
	if [ $? != 0 ]
	then
		stop_mds
		error "MDT(s) start failed"
	fi

	start_ost
	if [ $? != 0 ]
	then
		stop_mds
		stop ost1 -f
		error "OST(s) start failed"
	fi

	mount_client $MOUNT
	if [ $? != 0 ]
	then
		stop_mds
		stop ost1 -f
		error "client start failed"
	fi
	check_mount
	if [ $? != 0 ]
	then
		stop_mds
		stop ost1 -f
		error "client mount failed"
	fi
	cleanup
}
run_test 41c "concurrent mounts of MDT/OST should all fail but one"

test_42() { #bug 14693
	local PARAM

	setup
	check_mount || error "client was not mounted"

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		PARAM="llite.$FSNAME-*.some_wrong_param"
	else
		PARAM="$FSNAME.llite.some_wrong_param"
	fi

	do_facet mgs $PERM_CMD $PARAM=10
	umount_client $MOUNT ||
		error "unmounting client failed with invalid llite param"
	mount_client $MOUNT ||
		error "mounting client failed with invalid llite param"

	do_facet mgs $PERM_CMD $PARAM=20
	cleanup || error "stopping $FSNAME failed with invalid sys param"
	setup
	check_mount || error "client was not mounted with invalid sys param"
	cleanup || error "stopping $FSNAME failed with invalid sys param"
}
run_test 42 "allow client/server mount/unmount with invalid config param"

test_43a() {
	[[ "$MGS_VERSION" -ge $(version_code 2.5.58) ]] ||
		skip "Need MDS version at least 2.5.58"
	[ $UID -ne 0 -o $RUNAS_ID -eq 0 ] && skip_env "run as root"

	ID1=${ID1:-501}
	USER1=$(getent passwd | grep :$ID1:$ID1: | cut -d: -f1)
	[ -z "$USER1" ] && skip_env "missing user with uid=$ID1 gid=$ID1"

	setup
	chmod ugo+x $DIR || error "chmod 0 failed"
	set_persistent_param_and_check mds1				\
		"mdt.$FSNAME-MDT0000.root_squash"			\
		"$FSNAME.mdt.root_squash"				\
		"0:0"
	wait_update $HOSTNAME						\
		"$LCTL get_param -n llite.${FSNAME}*.root_squash"	\
		"0:0" ||
		error "check llite root_squash failed!"
	set_persistent_param_and_check mds1				\
		"mdt.$FSNAME-MDT0000.nosquash_nids"			\
		"$FSNAME.mdt.nosquash_nids"				\
		"NONE"
	wait_update $HOSTNAME						\
		"$LCTL get_param -n llite.${FSNAME}*.nosquash_nids"	\
		"NONE" ||
		error "check llite nosquash_nids failed!"

	#
	# create set of test files
	#
	echo "111" > $DIR/$tfile-userfile || error "write 1 failed"
	chmod go-rw $DIR/$tfile-userfile  || error "chmod 1 failed"
	chown $RUNAS_ID.$RUNAS_ID $DIR/$tfile-userfile || error "chown failed"

	echo "222" > $DIR/$tfile-rootfile || error "write 2 failed"
	chmod go-rw $DIR/$tfile-rootfile  || error "chmod 2 faield"

	mkdir_on_mdt0 $DIR/$tdir-rootdir || error "mkdir failed"
	chmod go-rwx $DIR/$tdir-rootdir || error "chmod 3 failed"
	touch $DIR/$tdir-rootdir/tfile-1 || error "touch failed"

	echo "777" > $DIR/$tfile-user1file || error "write 7 failed"
	chmod go-rw $DIR/$tfile-user1file || error "chmod 7 failed"
	chown $ID1.$ID1 $DIR/$tfile-user1file || error "chown failed"

	#
	# check root_squash:
	#   set root squash UID:GID to RUNAS_ID
	#   root should be able to access only files owned by RUNAS_ID
	#
	set_persistent_param_and_check mds1				\
		"mdt.$FSNAME-MDT0000.root_squash"			\
		"$FSNAME.mdt.root_squash"				\
		"$RUNAS_ID:$RUNAS_ID"
	wait_update $HOSTNAME						\
		"$LCTL get_param -n llite.${FSNAME}*.root_squash"	\
		"$RUNAS_ID:$RUNAS_ID" ||
		error "check llite root_squash failed!"

	ST=$(stat -c "%n: owner uid %u (%A)" $DIR/$tfile-userfile)
	dd if=$DIR/$tfile-userfile 1>/dev/null 2>/dev/null ||
		error "$ST: root read permission is denied"
	echo "$ST: root read permission is granted - ok"

	echo "444" |
	dd conv=notrunc of=$DIR/$tfile-userfile 1>/dev/null 2>/dev/null ||
		error "$ST: root write permission is denied"
	echo "$ST: root write permission is granted - ok"

	ST=$(stat -c "%n: owner uid %u (%A)" $DIR/$tfile-rootfile)
	dd if=$DIR/$tfile-rootfile 1>/dev/null 2>/dev/null &&
		error "$ST: root read permission is granted"
	echo "$ST: root read permission is denied - ok"

	echo "555" |
	dd conv=notrunc of=$DIR/$tfile-rootfile 1>/dev/null 2>/dev/null &&
		error "$ST: root write permission is granted"
	echo "$ST: root write permission is denied - ok"

	ST=$(stat -c "%n: owner uid %u (%A)" $DIR/$tdir-rootdir)
		rm $DIR/$tdir-rootdir/tfile-1 1>/dev/null 2>/dev/null &&
			error "$ST: root unlink permission is granted"
	echo "$ST: root unlink permission is denied - ok"

	touch $DIR/tdir-rootdir/tfile-2 1>/dev/null 2>/dev/null &&
		error "$ST: root create permission is granted"
	echo "$ST: root create permission is denied - ok"

	# LU-1778
	# check root_squash is enforced independently
	# of client cache content
	#
	# access file by USER1, keep access open
	# root should be denied access to user file

	runas -u $ID1 tail -f $DIR/$tfile-user1file 1>/dev/null 2>&1 &
	pid=$!
	sleep 1

	ST=$(stat -c "%n: owner uid %u (%A)" $DIR/$tfile-user1file)
	dd if=$DIR/$tfile-user1file 1>/dev/null 2>&1 &&
	    { kill $pid; error "$ST: root read permission is granted"; }
	echo "$ST: root read permission is denied - ok"

	echo "777" |
	dd conv=notrunc of=$DIR/$tfile-user1file 1>/dev/null 2>&1 &&
	    { kill $pid; error "$ST: root write permission is granted"; }
	echo "$ST: root write permission is denied - ok"

	kill $pid
	wait $pid

	#
	# check nosquash_nids:
	#   put client's NID into nosquash_nids list,
	#   root should be able to access root file after that
	#
	local NIDLIST=$($LCTL list_nids all | tr '\n' ' ')
	NIDLIST="2@gni $NIDLIST 192.168.0.[2,10]@tcp"
	NIDLIST=$(echo $NIDLIST | tr -s ' ' ' ')
	set_persistent_param_and_check mds1				\
		"mdt.$FSNAME-MDT0000.nosquash_nids"			\
		"$FSNAME-MDTall.mdt.nosquash_nids"			\
		"$NIDLIST"
	wait_update $HOSTNAME						\
		"$LCTL get_param -n llite.${FSNAME}*.nosquash_nids"	\
		"$NIDLIST" ||
		error "check llite nosquash_nids failed!"

	ST=$(stat -c "%n: owner uid %u (%A)" $DIR/$tfile-rootfile)
	dd if=$DIR/$tfile-rootfile 1>/dev/null 2>/dev/null ||
		error "$ST: root read permission is denied"
	echo "$ST: root read permission is granted - ok"

	echo "666" |
	dd conv=notrunc of=$DIR/$tfile-rootfile 1>/dev/null 2>/dev/null ||
		error "$ST: root write permission is denied"
	echo "$ST: root write permission is granted - ok"

	ST=$(stat -c "%n: owner uid %u (%A)" $DIR/$tdir-rootdir)
	rm $DIR/$tdir-rootdir/tfile-1 ||
		error "$ST: root unlink permission is denied"
	echo "$ST: root unlink permission is granted - ok"
	touch $DIR/$tdir-rootdir/tfile-2 ||
		error "$ST: root create permission is denied"
	echo "$ST: root create permission is granted - ok"
	cleanup || error "cleanup failed with $?"
}
run_test 43a "check root_squash and nosquash_nids"

test_43b() { # LU-5690
	[[ "$MGS_VERSION" -ge $(version_code 2.7.62) ]] ||
		skip "Need MGS version 2.7.62+"

	if [[ -z "$fs2mds_DEV" ]]; then
		is_blkdev $SINGLEMDS $(mdsdevname ${SINGLEMDS//mds/}) &&
		skip_env "mixed loopback and real device not working"
	fi

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)

	# temporarily use fs2mds as fs2mgs
	local fs2mgs=fs2mds
	local fs2mgsdev=$fs2mdsdev
	local fs2mgsvdev=$fs2mdsvdev

	local fsname=test1234

	load_module llite/lustre
	local client_ip=$(host_nids_address $HOSTNAME $NETTYPE)
	local host=${client_ip//*./}
	local net=${client_ip/%$host/}
	local nosquash_nids=$(h2nettype $net[$host,$host,$host])

	add $fs2mgs $(mkfs_opts mgs $fs2mgsdev) --fsname=$fsname \
		--param mdt.root_squash=$RUNAS_ID:$RUNAS_ID \
		--param mdt.nosquash_nids=$nosquash_nids \
		--reformat $fs2mgsdev $fs2mgsvdev || error "add fs2mgs failed"
	start $fs2mgs $fs2mgsdev $MGS_MOUNT_OPTS  || error "start fs2mgs failed"
	stop $fs2mgs -f || error "stop fs2mgs failed"
	cleanup || error "cleanup failed with $?"
}
run_test 43b "parse nosquash_nids with commas in expr_list"

test_44() { # 16317
	setup
	check_mount || error "check_mount"
	UUID=$($LCTL get_param llite.${FSNAME}*.uuid | cut -d= -f2)
	STATS_FOUND=no
        UUIDS=$(do_facet $SINGLEMDS "$LCTL get_param mdt.${FSNAME}*.exports.*.uuid")
        for VAL in $UUIDS; do
                NID=$(echo $VAL | cut -d= -f1)
                CLUUID=$(echo $VAL | cut -d= -f2)
                [ "$UUID" = "$CLUUID" ] && STATS_FOUND=yes && break
        done
	[ "$STATS_FOUND" = "no" ] && error "stats not found for client"
	cleanup || error "cleanup failed with $?"
}
run_test 44 "mounted client proc entry exists"

test_45() { #17310
	setup
	check_mount || error "check_mount"
	stop_mds || error "Unable to stop MDS"
	df -h $MOUNT &
	log "sleep 60 sec"
	sleep 60
	#define OBD_FAIL_PTLRPC_LONG_REPL_UNLINK	0x50f
	do_facet client "$LCTL set_param fail_loc=0x8000050f"
	log "sleep 10 sec"
	sleep 10
	manual_umount_client --force || error "manual_umount_client failed"
	do_facet client "$LCTL set_param fail_loc=0x0"
	start_mds || error "unable to start MDS"
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	cleanup || error "cleanup failed with $?"
}
run_test 45 "long unlink handling in ptlrpcd"

cleanup_46a() {
	trap 0
	local rc=0
	local count=$1

	umount_client $MOUNT2 || rc=$?
	umount_client $MOUNT || rc=$?
	while [ $count -gt 0 ]; do
		stop ost${count} -f || rc=$?
		let count=count-1
	done
	stop_mds || rc=$?
	cleanup_nocli || rc=$?
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
	return $rc
}

test_46a() {
	echo "Testing with $OSTCOUNT OSTs"
	reformat_and_config
	start_mds || error "unable to start MDS"
	#first client should see only one ost
	start_ost || error "Unable to start OST1"
        wait_osc_import_state mds ost FULL
	#start_client
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	trap "cleanup_46a $OSTCOUNT" EXIT ERR

	local i
	for (( i=2; i<=$OSTCOUNT; i++ )); do
		start ost$i $(ostdevname $i) $OST_MOUNT_OPTS ||
			error "start_ost$i $(ostdevname $i) failed"
	done

	# wait until osts in sync
	for (( i=2; i<=$OSTCOUNT; i++ )); do
	    wait_osc_import_state mds ost$i FULL
	    wait_osc_import_ready client ost$i
	done

	#second client see all ost's

	mount_client $MOUNT2 || error "mount_client failed"
	$LFS setstripe -c -1 $MOUNT2 ||
		error "$LFS setstripe -c -1 $MOUNT2 failed"
	$LFS getstripe $MOUNT2 || error "$LFS getstripe $MOUNT2 failed"

	echo "ok" > $MOUNT2/widestripe
	$LFS getstripe $MOUNT2/widestripe ||
		error "$LFS getstripe $MOUNT2/widestripe failed"
	# fill acl buffer for avoid expand lsm to them
	awk -F : '{if (FNR < 25) { print "u:"$1":rwx" }}' /etc/passwd |
		while read acl; do
	    setfacl -m $acl $MOUNT2/widestripe
	done

	# will be deadlock
	stat $MOUNT/widestripe || error "stat $MOUNT/widestripe failed"

	cleanup_46a $OSTCOUNT || error "cleanup_46a failed"
}
run_test 46a "handle ost additional - wide striped file"

test_47() { #17674
	reformat
	setup_noconfig
	check_mount || error "check_mount failed"
	$LCTL set_param ldlm.namespaces.$FSNAME-*-*-*.lru_size=100

        local lru_size=[]
        local count=0
        for ns in $($LCTL get_param ldlm.namespaces.$FSNAME-*-*-*.lru_size); do
            if echo $ns | grep "MDT[[:digit:]]*"; then
                continue
            fi
            lrs=$(echo $ns | sed 's/.*lru_size=//')
            lru_size[count]=$lrs
            let count=count+1
        done

	facet_failover ost1
	facet_failover $SINGLEMDS
	client_up || error "client_up failed"

        count=0
        for ns in $($LCTL get_param ldlm.namespaces.$FSNAME-*-*-*.lru_size); do
            if echo $ns | grep "MDT[[:digit:]]*"; then
                continue
            fi
            lrs=$(echo $ns | sed 's/.*lru_size=//')
            if ! test "$lrs" -eq "${lru_size[count]}"; then
                n=$(echo $ns | sed -e 's/ldlm.namespaces.//' -e 's/.lru_size=.*//')
                error "$n has lost lru_size: $lrs vs. ${lru_size[count]}"
            fi
            let count=count+1
        done

	cleanup || error "cleanup failed with $?"
}
run_test 47 "server restart does not make client loss lru_resize settings"

cleanup_48() {
	trap 0

	# reformat after this test is needed - if the test fails,
	# we will have unkillable file at FS
	reformat_and_config
}

test_48() { # bz-17636 LU-7473
	local count

	setup_noconfig
	check_mount || error "check_mount failed"

	$LFS setstripe -c -1 $MOUNT ||
		error "$LFS setstripe -c -1 $MOUNT failed"
	$LFS getstripe $MOUNT || error "$LFS getstripe $MOUNT failed"

	echo "ok" > $MOUNT/widestripe
	$LFS getstripe $MOUNT/widestripe ||
		error "$LFS getstripe $MOUNT/widestripe failed"

	# In the future, we may introduce more EAs, such as selinux, enlarged
	# LOV EA, and so on. These EA will use some EA space that is shared by
	# ACL entries. So here we only check some reasonable ACL entries count,
	# instead of the max number that is calculated from the max_ea_size.
	if [ "$MDS1_VERSION" -lt $(version_code 2.8.57) ]; then
		count=28	# hard coded of RPC protocol
	elif large_xattr_enabled; then
		count=4500	# max_num 8187 max_ea_size = 65452
				# not create too many (4500) to save test time
	else
		count=450	# max_num 497 max_ea_size = 4012
	fi

	echo "It is expected to hold at least $count ACL entries"
	trap cleanup_48 EXIT ERR
	for ((i = 0; i < $count; i++)) do
		setfacl -m u:$((i + 100)):rw $MOUNT/widestripe ||
			error "Fail to setfacl for $MOUNT/widestripe at $i"
	done

	cancel_lru_locks mdc
	stat $MOUNT/widestripe || error "stat $MOUNT/widestripe failed"
	local r_count=$(getfacl $MOUNT/widestripe | grep "user:" | wc -l)
	count=$((count + 1)) # for the entry "user::rw-"

	[ $count -eq $r_count ] ||
		error "Expected ACL entries $count, but got $r_count"

	cleanup_48
}
run_test 48 "too many acls on file"

# check PARAM_SYS_LDLM_TIMEOUT option of MKFS.LUSTRE
test_49a() { # bug 17710
	local timeout_orig=$TIMEOUT
	local ldlm_timeout_orig=$LDLM_TIMEOUT
	local LOCAL_TIMEOUT=20

	LDLM_TIMEOUT=$LOCAL_TIMEOUT
	TIMEOUT=$LOCAL_TIMEOUT

	reformat
	setup_noconfig
	check_mount || error "client mount failed"

	echo "check ldlm_timout..."
	local LDLM_MDS="$(do_facet $SINGLEMDS $LCTL get_param -n ldlm_timeout)"
	local LDLM_OST1="$(do_facet ost1 $LCTL get_param -n ldlm_timeout)"
	local LDLM_CLIENT="$(do_facet client $LCTL get_param -n ldlm_timeout)"

	if [ $LDLM_MDS -ne $LDLM_OST1 -o $LDLM_MDS -ne $LDLM_CLIENT ]; then
		error "Different LDLM_TIMEOUT:$LDLM_MDS $LDLM_OST1 $LDLM_CLIENT"
	fi

	if [ $LDLM_MDS -ne $((LOCAL_TIMEOUT / 3)) ]; then
		error "LDLM_TIMEOUT($LDLM_MDS) is not $((LOCAL_TIMEOUT / 3))"
	fi

	umount_client $MOUNT || error "umount_client $MOUNT failed"
	stop_ost || error "problem stopping OSS"
	stop_mds || error "problem stopping MDS"

	LDLM_TIMEOUT=$ldlm_timeout_orig
	TIMEOUT=$timeout_orig
}
run_test 49a "check PARAM_SYS_LDLM_TIMEOUT option of mkfs.lustre"

test_49b() { # bug 17710
	local timeout_orig=$TIMEOUT
	local ldlm_timeout_orig=$LDLM_TIMEOUT
	local LOCAL_TIMEOUT=20

	LDLM_TIMEOUT=$((LOCAL_TIMEOUT - 1))
	TIMEOUT=$LOCAL_TIMEOUT

	reformat
	setup_noconfig
	check_mount || error "client mount failed"

	local LDLM_MDS="$(do_facet $SINGLEMDS $LCTL get_param -n ldlm_timeout)"
	local LDLM_OST1="$(do_facet ost1 $LCTL get_param -n ldlm_timeout)"
	local LDLM_CLIENT="$(do_facet client $LCTL get_param -n ldlm_timeout)"

	if [ $LDLM_MDS -ne $LDLM_OST1 -o $LDLM_MDS -ne $LDLM_CLIENT ]; then
		error "Different LDLM_TIMEOUT:$LDLM_MDS $LDLM_OST1 $LDLM_CLIENT"
	fi

	if [ $LDLM_MDS -ne $((LOCAL_TIMEOUT - 1)) ]; then
		error "LDLM_TIMEOUT($LDLM_MDS) is not $((LOCAL_TIMEOUT - 1))"
	fi

	cleanup || error "cleanup failed"

	LDLM_TIMEOUT=$ldlm_timeout_orig
	TIMEOUT=$timeout_orig
}
run_test 49b "check PARAM_SYS_LDLM_TIMEOUT option of mkfs.lustre"

lazystatfs() {
	# wait long enough to exceed OBD_STATFS_CACHE_SECONDS = 1
	sleep 2
        # Test both statfs and lfs df and fail if either one fails
	multiop_bg_pause $1 f_
	RC=$?
	PID=$!
	killall -USR1 multiop
	[ $RC -ne 0 ] && log "lazystatfs multiop failed"
	wait $PID || { RC=$?; log "multiop return error "; }

	# wait long enough to exceed OBD_STATFS_CACHE_SECONDS = 1
	sleep 2
	$LFS df -l &
	PID=$!
	sleep 5
	if kill -s 0 $PID; then
		RC=1
		kill -s 9 $PID
		log "lazystatfs lfs df failed to complete in 5s"
	fi

	return $RC
}

test_50a() {
	setup
	$LCTL set_param llite.$FSNAME-*.lazystatfs=1
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"

	lazystatfs $MOUNT || error "lazystatfs failed but no down servers"

	cleanup || error "cleanup failed with rc $?"
}
run_test 50a "lazystatfs all servers available"

test_50b() {
	setup
	$LCTL set_param llite.$FSNAME-*.lazystatfs=1
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"

	# Wait for client to detect down OST
	stop_ost || error "Unable to stop OST1"
	wait_osc_import_state client ost DISCONN
	$LCTL dl
	log "OSCs should all be DISCONN"

	lazystatfs $MOUNT || error "lazystatfs should not return EIO"

	umount_client $MOUNT || error "Unable to unmount client"
	stop_mds || error "Unable to stop MDS"
}
run_test 50b "lazystatfs all servers down"

test_50c() {
	start_mds || error "Unable to start MDS"
	start_ost || error "Unable to start OST1"
	start_ost2 || error "Unable to start OST2"
	mount_client $MOUNT || error "Unable to mount client"
	$LCTL set_param llite.$FSNAME-*.lazystatfs=1
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"

	# Wait for client to detect down OST
	stop_ost || error "Unable to stop OST1"
        wait_osc_import_state mds ost DISCONN
	lazystatfs $MOUNT || error "lazystatfs failed with one down server"

	umount_client $MOUNT || error "Unable to unmount client"
	stop_ost2 || error "Unable to stop OST2"
	stop_mds || error "Unable to stop MDS"
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 50c "lazystatfs one server down"

test_50d() {
	start_mds || error "Unable to start MDS"
	start_ost || error "Unable to start OST1"
	start_ost2 || error "Unable to start OST2"
	mount_client $MOUNT || error "Unable to mount client"
	$LCTL set_param llite.$FSNAME-*.lazystatfs=1
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"

	# Issue the statfs during the window where the client still
	# belives the OST to be available but it is in fact down.
	# No failure just a statfs which hangs for a timeout interval.
	stop_ost || error "Unable to stop OST1"
	lazystatfs $MOUNT || error "lazystatfs failed with one down server"

	umount_client $MOUNT || error "Unable to unmount client"
	stop_ost2 || error "Unable to stop OST2"
	stop_mds || error "Unable to stop MDS"
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 50d "lazystatfs client/server conn race"

test_50e() {
	local RC1
	local pid

	reformat_and_config
	start_mds || error "Unable to start MDS"
	#first client should see only one ost
	start_ost || error "Unable to start OST1"
	wait_osc_import_state mds ost FULL

	# Wait for client to detect down OST
	stop_ost || error "Unable to stop OST1"
	wait_osc_import_state mds ost DISCONN

	mount_client $MOUNT || error "Unable to mount client"
	$LCTL set_param llite.$FSNAME-*.lazystatfs=0

	multiop_bg_pause $MOUNT _f
	RC1=$?
	pid=$!

	if [ $RC1 -ne 0 ]; then
		log "multiop failed $RC1"
	else
	    kill -USR1 $pid
	    sleep $(( $TIMEOUT+1 ))
	    kill -0 $pid
	    [ $? -ne 0 ] && error "process isn't sleep"
	    start_ost || error "Unable to start OST1"
	    wait $pid || error "statfs failed"
	fi

	umount_client $MOUNT || error "Unable to unmount client"
	stop_ost || error "Unable to stop OST1"
	stop_mds || error "Unable to stop MDS"
}
run_test 50e "normal statfs all servers down"

test_50f() {
	local RC1
	local pid
	CONN_PROC="osc.$FSNAME-OST0001-osc-[M]*.ost_server_uuid"

	start_mds || error "Unable to start mds"
	#first client should see only one ost
	start_ost || error "Unable to start OST1"
        wait_osc_import_state mds ost FULL

        start_ost2 || error "Unable to start OST2"
        wait_osc_import_state mds ost2 FULL

	# Wait for client to detect down OST
	stop_ost2 || error "Unable to stop OST2"

	wait_osc_import_state mds ost2 DISCONN
	mount_client $MOUNT || error "Unable to mount client"
	$LCTL set_param llite.$FSNAME-*.lazystatfs=0

	multiop_bg_pause $MOUNT _f
	RC1=$?
	pid=$!

	if [ $RC1 -ne 0 ]; then
		log "lazystatfs multiop failed $RC1"
	else
	    kill -USR1 $pid
	    sleep $(( $TIMEOUT+1 ))
	    kill -0 $pid
	    [ $? -ne 0 ] && error "process isn't sleep"
	    start_ost2 || error "Unable to start OST2"
	    wait $pid || error "statfs failed"
	    stop_ost2 || error "Unable to stop OST2"
	fi

	umount_client $MOUNT -f || error "Unable to unmount client"
	stop_ost || error "Unable to stop OST1"
	stop_mds || error "Unable to stop MDS"
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 50f "normal statfs one server in down"

test_50g() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "needs >=2 OSTs"
	setup
	start_ost2 || error "Unable to start OST2"
	wait_osc_import_state mds ost2 FULL
	wait_osc_import_ready client ost2

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		local PARAM="osc.${FSNAME}-OST0001*.active"
	else
		local PARAM="${FSNAME}-OST0001.osc.active"
	fi

	$LFS setstripe -c -1 $DIR/$tfile || error "$LFS setstripe failed"
	do_facet mgs $PERM_CMD $PARAM=0 || error "Unable to deactivate OST"

	umount_client $MOUNT || error "Unable to unmount client"
	mount_client $MOUNT || error "Unable to mount client"
	# This df should not cause a panic
	df -k $MOUNT

	do_facet mgs $PERM_CMD $PARAM=1 || error "Unable to activate OST"
	rm -f $DIR/$tfile || error "unable to remove file $DIR/$tfile"
	umount_client $MOUNT || error "Unable to unmount client"
	stop_ost2 || error "Unable to stop OST2"
	stop_ost || error "Unable to stop OST1"
	stop_mds || error "Unable to stop MDS"
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 50g "deactivated OST should not cause panic"

# LU-642
test_50h() {
	# prepare MDT/OST, make OSC inactive for OST1
	[ "$OSTCOUNT" -lt "2" ] && skip_env "needs >=2 OSTs"

	[ "$ost1_FSTYPE" == zfs ] && import_zpool ost1
	do_facet ost1 "$TUNEFS --param osc.active=0 `ostdevname 1`" ||
		error "tunefs OST1 failed"
	start_mds  || error "Unable to start MDT"
	start_ost  || error "Unable to start OST1"
	start_ost2 || error "Unable to start OST2"
	mount_client $MOUNT || error "client start failed"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	# activatate OSC for OST1
	set_persistent_param_and_check client		 \
		"osc.${FSNAME}-OST0000-osc-[!M]*.active" \
		"${FSNAME}-OST0000.osc.active" 1

	mkdir $DIR/$tdir/2 || error "mkdir $DIR/$tdir/2 failed"
	$LFS setstripe -c -1 -i 0 $DIR/$tdir/2 ||
		error "$LFS setstripe $DIR/$tdir/2 failed"
	sleep 1 && echo "create a file after OST1 is activated"
	# doing some io, shouldn't crash
	dd if=/dev/zero of=$DIR/$tdir/2/$tfile-io bs=1M count=10

	# check OSC import is working
	stat $DIR/$tdir/2/* >/dev/null 2>&1 ||
		error "some OSC imports are still not connected"

	# cleanup
	rm -rf $DIR/$tdir
	umount_client $MOUNT || error "Unable to umount client"
	stop_ost2 || error "Unable to stop OST2"
	cleanup_nocli || error "cleanup_nocli failed with $?"
}
run_test 50h "LU-642: activate deactivated OST"

test_50i() {
	# prepare MDT/OST, make OSC inactive for OST1
	[ "$MDSCOUNT" -lt "2" ] && skip "needs >= 2 MDTs"

	load_modules
	[ $(facet_fstype mds2) == zfs ] && import_zpool mds2
	do_facet mds2 "$TUNEFS --param mdc.active=0 $(mdsdevname 2)" ||
		error "tunefs MDT2 failed"
	start_mds  || error "Unable to start MDT"
	start_ost  || error "Unable to start OST1"
	start_ost2 || error "Unable to start OST2"
	mount_client $MOUNT || error "client start failed"

	mkdir_on_mdt0 $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		$PERM_CMD mdc.${FSNAME}-MDT0001-mdc-*.active=0 &&
			error "deactive MDC0 succeeds"
	else
		$PERM_CMD ${FSNAME}-MDT0000.mdc.active=0 &&
			error "deactive MDC0 succeeds"
	fi

	# activate MDC for MDT2
	set_persistent_param_and_check client		 \
		"mdc.${FSNAME}-MDT0001-mdc-*.active" \
		"${FSNAME}-MDT0001.mdc.active" 1

	wait_clients_import_state ${CLIENTS:-$HOSTNAME} mds2 FULL
	if [ "$MDS1_VERSION" -ge $(version_code 2.7.60) ]
	then
		wait_dne_interconnect
	fi
	$LFS mkdir -i1 $DIR/$tdir/2 || error "mkdir $DIR/$tdir/2 failed"
	# create some file
	createmany -o $DIR/$tdir/2/$tfile-%d 1 || error "create files failed"

	rm -rf $DIR/$tdir/2 || error "unlink dir failed"

	# deactivate MDC for MDT2
	set_persistent_param_and_check client		\
		"mdc.${FSNAME}-MDT0001-mdc-*.active"	\
		"${FSNAME}-MDT0001.mdc.active" 0

	wait_osp_active mds ${FSNAME}-MDT0001 1 0

	$LFS mkdir -i1 $DIR/$tdir/2 &&
		error "mkdir $DIR/$tdir/2 succeeds after deactive MDT"

	$LFS mkdir -i0 -c$MDSCOUNT $DIR/$tdir/striped_dir ||
		error "mkdir $DIR/$tdir/striped_dir fails after deactive MDT2"

	local stripe_count=$($LFS getdirstripe -c $DIR/$tdir/striped_dir)
	[ $stripe_count -eq $((MDSCOUNT - 1)) ] ||
		error "wrong $stripe_count != $((MDSCOUNT -1)) for striped_dir"

	# cleanup
	umount_client $MOUNT || error "Unable to umount client"
	stop_mds
	stop_ost
	stop_ost 2
}
run_test 50i "activate deactivated MDT"

test_51() {
	local LOCAL_TIMEOUT=20

	reformat
	setup_noconfig
	check_mount || error "check_mount failed"

	mkdir $MOUNT/$tdir || error "mkdir $MOUNT/$tdir failed"
	$LFS setstripe -c -1 $MOUNT/$tdir ||
		error "$LFS setstripe -c -1 $MOUNT/$tdir failed"
	#define OBD_FAIL_MDS_REINT_DELAY         0x142
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x142"
	touch $MOUNT/$tdir/$tfile &
	local pid=$!
	sleep 2
	start_ost2 || error "Unable to start OST1"
	wait $pid
	stop_ost2 || error "Unable to stop OST1"
	umount_client $MOUNT -f || error “unmount $MOUNT failed”
	cleanup_nocli || error “stop server failed”
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 51 "Verify that mdt_reint handles RMF_MDT_MD correctly when an OST is added"

copy_files_xattrs()
{
	local node=$1
	local dest=$2
	local xattrs=$3
	shift 3

	do_node $node mkdir -p $dest
	[ $? -eq 0 ] || { error "Unable to create directory"; return 1; }

	do_node $node  'tar cf - '$@' | tar xf - -C '$dest';
			[ \"\${PIPESTATUS[*]}\" = \"0 0\" ] || exit 1'
	[ $? -eq 0 ] || { error "Unable to tar files"; return 2; }

	do_node $node 'getfattr -d -m "[a-z]*\\." '$@' > '$xattrs
	[ $? -eq 0 ] || { error "Unable to read xattrs"; return 3; }
}

diff_files_xattrs()
{
	local node=$1
	local backup=$2
	local xattrs=$3
	shift 3

	local backup2=${TMP}/backup2

	do_node $node mkdir -p $backup2
	[ $? -eq 0 ] || { error "Unable to create directory"; return 1; }

	do_node $node  'tar cf - '$@' | tar xf - -C '$backup2';
			[ \"\${PIPESTATUS[*]}\" = \"0 0\" ] || exit 1'
	[ $? -eq 0 ] || { error "Unable to tar files to diff"; return 2; }

	do_node $node "diff -rq $backup $backup2"
	[ $? -eq 0 ] || { error "contents differ"; return 3; }

	local xattrs2=${TMP}/xattrs2
	do_node $node 'getfattr -d -m "[a-z]*\\." '$@' > '$xattrs2
	[ $? -eq 0 ] || { error "Unable to read xattrs to diff"; return 4; }

	do_node $node "diff $xattrs $xattrs2"
	[ $? -eq 0 ] || { error "xattrs differ"; return 5; }

	do_node $node "rm -rf $backup2 $xattrs2"
	[ $? -eq 0 ] || { error "Unable to delete temporary files"; return 6; }
}

test_52() {
	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi

	start_mds || error "Unable to start MDS"
	start_ost || error "Unable to start OST1"
	mount_client $MOUNT || error "Unable to mount client"

	local nrfiles=8
	local ost1mnt=$(facet_mntpt ost1)
	local ost1node=$(facet_active_host ost1)
	local ost1tmp=$TMP/conf52
	local loop

	mkdir $DIR/$tdir || error "Unable to create $DIR/$tdir"
	touch $TMP/modified_first || error "Unable to create temporary file"
	local mtime=$(stat -c %Y $TMP/modified_first)
	do_node $ost1node "mkdir -p $ost1tmp &&
			   touch -m -d @$mtime $ost1tmp/modified_first" ||
		error "Unable to create temporary file"
	sleep 1

	$LFS setstripe -c -1 -S 1M $DIR/$tdir || error "$LFS setstripe failed"

	for (( i=0; i < nrfiles; i++ )); do
		multiop $DIR/$tdir/$tfile-$i Ow1048576w1048576w524288c ||
			error "multiop failed"
		echo -n .
	done
	echo

	# sync all the data and make sure no pending data on the client,
	# thus the SOM xattr would not be changed any more.
	cancel_lru_locks osc

	# backup files
	echo backup files to $TMP/$tdir
	local files=$(find $DIR/$tdir -type f -newer $TMP/modified_first)
	copy_files_xattrs $(hostname) $TMP/$tdir $TMP/file_xattrs $files ||
		error "Unable to copy files"

	umount_client $MOUNT || error "Unable to umount client"
	stop_ost || error "Unable to stop ost1"

	echo mount ost1 as ldiskfs
	do_node $ost1node mkdir -p $ost1mnt || error "Unable to create $ost1mnt"
	if ! do_node $ost1node test -b $ost1_dev; then
		loop="-o loop"
	fi
	do_node $ost1node mount -t "$ost1_FSTYPE" $loop $ost1_dev \
		$ost1mnt ||
		error "Unable to mount ost1 as ldiskfs"

	# backup objects
	echo backup objects to $ost1tmp/objects
	local objects=$(do_node $ost1node 'find '$ost1mnt'/O/[0-9]* -type f'\
		'-size +0 -newer '$ost1tmp'/modified_first -regex ".*\/[0-9]+"')
	copy_files_xattrs $ost1node $ost1tmp/objects $ost1tmp/object_xattrs \
			$objects ||
		error "Unable to copy objects"

	# move objects to lost+found
	do_node $ost1node 'mv '$objects' '${ost1mnt}'/lost+found'
	[ $? -eq 0 ] || { error "Unable to move objects"; return 14; }

	do_node $ost1node "umount $ost1mnt" ||
		error "Unable to umount ost1 as ldiskfs"

	start_ost || error "Unable to start OST1"
	mount_client $MOUNT || error "Unable to mount client"

	local REPAIRED=$(do_node $ost1node "$LCTL get_param \
			 -n osd-ldiskfs.$FSNAME-OST0000.oi_scrub" |
			 awk '/^lf_repa[ri]*ed/ { print $2 }')
	[ $REPAIRED -gt 0 ] ||
		error "Some entry under /lost+found should be repaired"

	# compare files
	diff_files_xattrs $(hostname) $TMP/$tdir $TMP/file_xattrs $files ||
		error "Unable to diff files"

	rm -rf $TMP/$tdir $TMP/file_xattrs ||
		error "Unable to delete temporary files"
	do_node $ost1node "rm -rf $ost1tmp" ||
		error "Unable to delete temporary files"
	cleanup || error "cleanup failed with $?"
}
run_test 52 "check recovering objects from lost+found"

# Checks threads_min/max/started for some service
#
# Arguments: service name (OST or MDT), facet (e.g., ost1, $SINGLEMDS), and a
# parameter pattern prefix like 'ost.*.ost'.
thread_sanity() {
        local modname=$1
        local facet=$2
        local parampat=$3
        local opts=$4
	local basethr=$5
        local tmin
        local tmin2
        local tmax
        local tmax2
        local tstarted
        local paramp
        local msg="Insane $modname thread counts"
	local ncpts=$(check_cpt_number $facet)
	local nthrs
        shift 4

        check_mount || return 41

        # We need to expand $parampat, but it may match multiple parameters, so
        # we'll pick the first one
        if ! paramp=$(do_facet $facet "lctl get_param -N ${parampat}.threads_min"|head -1); then
                error "Couldn't expand ${parampat}.threads_min parameter name"
                return 22
        fi

	# Remove the .threads_min part
	paramp=${paramp%.threads_min}

	# Check for sanity in defaults
	tmin=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_min" ||
	       echo 0)
	tmax=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_max" ||
	       echo 0)
	tstarted=$(do_facet $facet "$LCTL get_param \
				    -n ${paramp}.threads_started" || echo 0)
	lassert 23 "$msg (PDSH problems?)" '(($tstarted && $tmin && $tmax))' ||
		return $?
	lassert 24 "$msg" '(($tstarted >= $tmin && $tstarted <= $tmax ))' ||
		return $?
	nthrs=$(expr $tmax - $tmin)
	if [ $nthrs -lt $ncpts ]; then
		nthrs=0
	else
		nthrs=$ncpts
	fi

	[ $tmin -eq $tmax -a $tmin -eq $tstarted ] &&
		skip_env "module parameter forced $facet thread count"

	# Check that we can change min/max
	do_facet $facet "$LCTL set_param \
			 ${paramp}.threads_min=$((tmin + nthrs))"
	do_facet $facet "$LCTL set_param \
			 ${paramp}.threads_max=$((tmax - nthrs))"
	tmin2=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_min" ||
		echo 0)
	tmax2=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_max" ||
		echo 0)
	lassert 25 "$msg" '(($tmin2 == ($tmin + $nthrs) &&
			    $tmax2 == ($tmax - $nthrs)))' || return $?

	# Check that we can set min/max to the same value
	tmin=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_min" ||
	       echo 0)
	do_facet $facet "$LCTL set_param ${paramp}.threads_max=$tmin"
	tmin2=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_min" ||
		echo 0)
	tmax2=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_max" ||
		echo 0)
	lassert 26 "$msg" '(($tmin2 == $tmin && $tmax2 == $tmin))' || return $?

	# Check that we can't set max < min
	do_facet $facet "$LCTL set_param ${paramp}.threads_max=$((tmin - 1))"
	tmin2=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_min" ||
		echo 0)
	tmax2=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_max" ||
		echo 0)
	lassert 27 "$msg" '(($tmin2 <= $tmax2))' || return $?

	# We need to ensure that we get the module options desired; to do this
	# we set LOAD_MODULES_REMOTE=true and we call setmodopts below.
	LOAD_MODULES_REMOTE=true
	cleanup
	local oldvalue
	local newvalue="${opts}=$(expr $basethr \* $ncpts)"
	setmodopts -a $modname "$newvalue" oldvalue

	setup
	check_mount || return 41

	# Restore previous setting of MODOPTS_*
	setmodopts $modname "$oldvalue"

	# Check that $opts took
	tmin=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_min" ||
		echo 0)
	tmax=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_max" ||
		echo 0)
	tstarted=$(do_facet $facet \
		   "$LCTL get_param -n ${paramp}.threads_started" || echo 0)
	lassert 28 "$msg" '(($tstarted >= $tmin && $tstarted <= $tmax ))' ||
		return $?
	cleanup

	setup
}

test_53a() {
	setup
	thread_sanity OST ost1 'ost.*.ost' 'oss_num_threads' '16'
	cleanup || error "cleanup failed with rc $?"
}
run_test 53a "check OSS thread count params"

test_53b() {
	setup
	local mds=$(do_facet $SINGLEMDS "$LCTL get_param \
					 -N mds.*.*.threads_max 2>/dev/null")
	if [ -z "$mds" ]; then
		#running this on an old MDT
		thread_sanity MDT $SINGLEMDS 'mdt.*.*.' 'mdt_num_threads' 16
	else
		thread_sanity MDT $SINGLEMDS 'mds.*.*.' 'mds_num_threads' 16
	fi
	cleanup || error "cleanup failed with $?"
}
run_test 53b "check MDS thread count params"

test_54a() {
	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi

	do_rpc_nodes $(facet_host ost1) run_llverdev $(ostdevname 1) -p ||
		error "llverdev failed with rc=$?"
	reformat_and_config
}
run_test 54a "test llverdev and partial verify of device"

test_54b() {
	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi

	setup
	run_llverfs $MOUNT -p || error "llverfs failed with rc=$?"
	cleanup || error "cleanup failed with rc=$?"
}
run_test 54b "test llverfs and partial verify of filesystem"

lov_objid_size()
{
	local max_ost_index=$1
	echo -n $(((max_ost_index + 1) * 8))
}

test_55() {
	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi

	local mdsdev=$(mdsdevname 1)
	local mdsvdev=$(mdsvdevname 1)

	for i in 1023 2048
	do
		if ! combined_mgs_mds; then
			stop_mgs || error "stopping MGS service failed"
			format_mgs || error "formatting MGT failed"
		fi
		add mds1 $(mkfs_opts mds1 ${mdsdev}) --reformat $mdsdev \
			$mdsvdev || exit 10
		add ost1 $(mkfs_opts ost1 $(ostdevname 1)) --index=$i \
			--reformat $(ostdevname 1) $(ostvdevname 1)
		setup_noconfig
		stopall
		setup_noconfig
		sync

		echo checking size of lov_objid for ost index $i
		LOV_OBJID_SIZE=$(do_facet mds1 "$DEBUGFS -R 'stat lov_objid' $mdsdev 2>/dev/null" |
				 grep ^User | awk -F 'Size: ' '{print $2}')
		if [ "$LOV_OBJID_SIZE" != $(lov_objid_size $i) ]; then
			error "lov_objid size has to be $(lov_objid_size $i), not $LOV_OBJID_SIZE"
		else
			echo ok, lov_objid size is correct: $LOV_OBJID_SIZE
		fi
		stopall
	done

	reformat_and_config
}
run_test 55 "check lov_objid size"

test_56a() {
	local mds_journal_size_orig=$MDSJOURNALSIZE
	local n

	MDSJOURNALSIZE=16

	formatall
	add ost1 $(mkfs_opts ost1 $(ostdevname 1)) --index=10000 --reformat \
		$(ostdevname 1) $(ostvdevname 1)
	add ost2 $(mkfs_opts ost2 $(ostdevname 2)) --index=1000 --reformat \
		$(ostdevname 2) $(ostvdevname 2)

	start_mgsmds
	start_ost || error "Unable to start first ost (idx 10000)"
	start_ost2 || error "Unable to start second ost (idx 1000)"
	mount_client $MOUNT || error "Unable to mount client"
	echo ok
	$LFS osts

	if [[ "$MDS1_VERSION" -ge $(version_code 2.6.54) ]] ||
	   [[ "$MDS1_VERSION" -ge $(version_code 2.5.4) &&
	      "$MDS1_VERSION" -lt $(version_code 2.5.11) ]]; then
		wait_osc_import_state mds ost1 FULL
		wait_osc_import_state mds ost2 FULL
		$LFS setstripe --stripe-count=-1 $DIR/$tfile ||
			error "Unable to setstripe $DIR/$tfile"
		n=$($LFS getstripe --stripe-count $DIR/$tfile)
		[ "$n" -eq 2 ] || error "Stripe count not two: $n"
		rm $DIR/$tfile
	fi

	stopall
	MDSJOURNALSIZE=$mds_journal_size_orig
	reformat_and_config
}
run_test 56a "check big OST indexes and out-of-index-order start"

cleanup_56b() {
	trap 0

	umount_client $MOUNT -f || error "unmount client failed"
	stop mds1
	stop mds2
	stop mds3
	stopall
	reformat_and_config
}

test_56b() {
	[ $MDSCOUNT -lt 3 ] && skip "needs >= 3 MDTs"

	trap cleanup_56b EXIT RETURN ERR
	stopall

	if ! combined_mgs_mds ; then
		format_mgs
		start_mgs
	fi

	add mds1 $(mkfs_opts mds1 $(mdsdevname 1)) --index=0 --reformat \
		$(mdsdevname 1) $(mdsvdevname 1)
	add mds2 $(mkfs_opts mds2 $(mdsdevname 2)) --index=1 --reformat \
		$(mdsdevname 2) $(mdsvdevname 2)
	add mds3 $(mkfs_opts mds3 $(mdsdevname 3)) --index=1000 --reformat \
		$(mdsdevname 3) $(mdsvdevname 3)
	format_ost 1
	format_ost 2

	start_mdt 1 || error "MDT 1 (idx 0) start failed"
	start_mdt 2 || error "MDT 2 (idx 1) start failed"
	start_mdt 3 || error "MDT 3 (idx 1000) start failed"
	start_ost || error "Unable to start first ost"
	start_ost2 || error "Unable to start second ost"

	do_nodes $(comma_list $(mdts_nodes)) \
		"$LCTL set_param mdt.*.enable_remote_dir=1 \
		mdt.*.enable_remote_dir_gid=-1"

	mount_client $MOUNT || error "Unable to mount client"

	$LFS mkdir -c3 $MOUNT/$tdir || error "failed to make testdir"

	echo "This is test file 1!" > $MOUNT/$tdir/$tfile.1 ||
		error "failed to make test file 1"
	echo "This is test file 2!" > $MOUNT/$tdir/$tfile.2 ||
		error "failed to make test file 2"
	echo "This is test file 1000!" > $MOUNT/$tdir/$tfile.1000 ||
		error "failed to make test file 1000"

	rm -rf $MOUNT/$tdir || error "failed to remove testdir"

	$LFS mkdir -i1000 $MOUNT/$tdir.1000 ||
		error "create remote dir at idx 1000 failed"

	output=$($LFS df)
	echo "=== START lfs df OUTPUT ==="
	echo -e "$output"
	echo "==== END lfs df OUTPUT ===="

	mdtcnt=$(echo -e "$output" | grep $FSNAME-MDT | wc -l)
	ostcnt=$(echo -e "$output" | grep $FSNAME-OST | wc -l)

	echo "lfs df returned mdt count $mdtcnt and ost count $ostcnt"
	[ $mdtcnt -eq 3 ] || error "lfs df returned wrong mdt count"
	[ $ostcnt -eq 2 ] || error "lfs df returned wrong ost count"

	echo "This is test file 1!" > $MOUNT/$tdir.1000/$tfile.1 ||
		error "failed to make test file 1"
	echo "This is test file 2!" > $MOUNT/$tdir.1000/$tfile.2 ||
		error "failed to make test file 2"
	echo "This is test file 1000!" > $MOUNT/$tdir.1000/$tfile.1000 ||
		error "failed to make test file 1000"
	rm -rf $MOUNT/$tdir.1000 || error "failed to remove remote_dir"

	output=$($LFS mdts)
	echo "=== START lfs mdts OUTPUT ==="
	echo -e "$output"
	echo "==== END lfs mdts OUTPUT ===="

	echo -e "$output" | grep -v "MDTS:" | awk '{print $1}' |
		sed 's/://g' > $TMP/mdts-actual.txt
	sort $TMP/mdts-actual.txt -o $TMP/mdts-actual.txt

	echo -e "0\n1\n1000" > $TMP/mdts-expected.txt

	diff $TMP/mdts-expected.txt $TMP/mdts-actual.txt
	result=$?

	rm $TMP/mdts-expected.txt $TMP/mdts-actual.txt

	[ $result -eq 0 ] || error "target_obd proc file is incorrect!"
}
run_test 56b "test target_obd correctness with nonconsecutive MDTs"

test_57a() { # bug 22656
	do_rpc_nodes $(facet_active_host ost1) load_modules_local
	local NID=$(do_facet ost1 "$LCTL get_param nis" |
		    tail -1 | awk '{print $1}')
	writeconf_or_reformat
	[ "$ost1_FSTYPE" == zfs ] && import_zpool ost1
	do_facet ost1 "$TUNEFS --failnode=$NID `ostdevname 1`" ||
		error "tunefs failed"
	start_mgsmds
	start_ost && error "OST registration from failnode should fail"
	cleanup
}
run_test 57a "initial registration from failnode should fail (should return errs)"

test_57b() {
	do_rpc_nodes $(facet_active_host ost1) load_modules_local
	local NID=$(do_facet ost1 "$LCTL get_param nis" |
		    tail -1 | awk '{print $1}')
	writeconf_or_reformat
	[ "$ost1_FSTYPE" == zfs ] && import_zpool ost1
	do_facet ost1 "$TUNEFS --servicenode=$NID `ostdevname 1`" ||
		error "tunefs failed"
	start_mgsmds
	start_ost || error "OST registration from servicenode should not fail"
	cleanup
}
run_test 57b "initial registration from servicenode should not fail"

count_osts() {
        do_facet mgs $LCTL get_param mgs.MGS.live.$FSNAME | grep OST | wc -l
}

test_58() { # bug 22658
	combined_mgs_mds || stop_mgs || error "stopping MGS service failed"
	setup_noconfig
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	createmany -o $DIR/$tdir/$tfile-%d 100
	unlinkmany $DIR/$tdir/$tfile-%d 100
	stop_mds || error "Unable to stop MDS"

	local MNTDIR=$(facet_mntpt $SINGLEMDS)
	local devname=$(mdsdevname ${SINGLEMDS//mds/})

	# remove all files from the OBJECTS dir
	mount_fstype $SINGLEMDS

	do_facet $SINGLEMDS "find $MNTDIR/O/1/d* -type f -delete"

	unmount_fstype $SINGLEMDS
	# restart MDS with missing llog files
	start_mds || error "unable to start MDS"
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0"
	cleanup
}
run_test 58 "missing llog files must not prevent MDT from mounting"

test_59() {
	start_mgsmds >> /dev/null
	local C1=$(count_osts)
	if [ $C1 -eq 0 ]; then
		start_ost >> /dev/null
		C1=$(count_osts)
	fi
	stopall
	echo "original ost count: $C1 (expect > 0)"
	[ $C1 -gt 0 ] || error "No OSTs in $FSNAME log"
	start_mgsmds -o writeconf >> /dev/null || error "MDT start failed"
	local C2=$(count_osts)
	echo "after mdt writeconf count: $C2 (expect 0)"
	[ $C2 -gt 0 ] && error "MDT writeconf should erase OST logs"
	echo "OST start without writeconf should fail:"
	start_ost >> /dev/null &&
		error "OST start without writeconf didn't fail"
	echo "OST start with writeconf should succeed:"
	start_ost -o writeconf >> /dev/null || error "OST1 start failed"
	local C3=$(count_osts)
	echo "after ost writeconf count: $C3 (expect 1)"
	[ $C3 -eq 1 ] || error "new OST writeconf should add:"
	start_ost2 -o writeconf >> /dev/null || error "OST2 start failed"
	local C4=$(count_osts)
	echo "after ost2 writeconf count: $C4 (expect 2)"
	[ $C4 -eq 2 ] || error "OST2 writeconf should add log"
	stop_ost2 >> /dev/null
	cleanup_nocli >> /dev/null
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 59 "writeconf mount option"

test_60() { # LU-471
	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi

	local num

	for num in $(seq $MDSCOUNT); do
		add mds${num} $(mkfs_opts mds${num} $(mdsdevname $num)) \
			--mkfsoptions='\" -E stride=64 -O ^uninit_bg\"' \
			--reformat $(mdsdevname $num) $(mdsvdevname $num) ||
			exit 10
	done

	dump=$(do_facet $SINGLEMDS dumpe2fs $(mdsdevname 1))
	[ ${PIPESTATUS[0]} -eq 0 ] || error "dumpe2fs $(mdsdevname 1) failed"

	# MDT default has dirdata feature
	echo $dump | grep dirdata > /dev/null || error "dirdata is not set"
	# we disable uninit_bg feature
	echo $dump | grep uninit_bg > /dev/null && error "uninit_bg is set"
	# we set stride extended options
	echo $dump | grep stride > /dev/null || error "stride is not set"
	stop_mds
	reformat_and_config
}
run_test 60 "check mkfs.lustre --mkfsoptions -E -O options setting"

test_61() { # LU-80
	local lxattr=$(large_xattr_enabled)

	[ "$MDS1_VERSION" -ge $(version_code 2.1.53) ] ||
		skip "Need MDS version at least 2.1.53"

	if [ "$mds1_FSTYPE" == ldiskfs ] &&
	     ! large_xattr_enabled; then
		lxattr=true

		for num in $(seq $MDSCOUNT); do
			do_facet mds${num} $TUNE2FS -O ea_inode \
				$(mdsdevname $num) ||
				error "tune2fs on mds $num failed"
		done
	fi

	setup || error "setting up the filesystem failed"
	client_up || error "starting client failed"

	local file=$DIR/$tfile
	touch $file || error "touch $file failed"

	local large_value="$(generate_string $(max_xattr_size))"
	local small_value="bar"

	local name="trusted.big"
	log "save large xattr of $(max_xattr_size) bytes on $name on $file"
	setfattr -n $name -v $large_value $file ||
		error "saving $name on $file failed"

	local new_value=$(get_xattr_value $name $file)
	[[ "$new_value" != "$large_value" ]] &&
		error "$name different after saving"

	log "shrink value of $name on $file"
	setfattr -n $name -v $small_value $file ||
		error "shrinking value of $name on $file failed"

	new_value=$(get_xattr_value $name $file)
	[[ "$new_value" != "$small_value" ]] &&
		error "$name different after shrinking"

	log "grow value of $name on $file"
	setfattr -n $name -v $large_value $file ||
		error "growing value of $name on $file failed"

	new_value=$(get_xattr_value $name $file)
	[[ "$new_value" != "$large_value" ]] &&
		error "$name different after growing"

	log "check value of $name on $file after remounting MDS"
	fail $SINGLEMDS
	new_value=$(get_xattr_value $name $file)
	[[ "$new_value" != "$large_value" ]] &&
		error "$name different after remounting MDS"

	log "remove large xattr $name from $file"
	setfattr -x $name $file || error "removing $name from $file failed"

	if $lxattr && [ "$mds1_FSTYPE" == ldiskfs ]; then
		stopall || error "stopping for e2fsck run"
		for num in $(seq $MDSCOUNT); do
			run_e2fsck $(facet_active_host mds$num) \
				$(mdsdevname $num) "-y" ||
				error "e2fsck MDT$num failed"
		done
		setup_noconfig || error "remounting the filesystem failed"
	fi

	# need to delete this file to avoid problems in other tests
	rm -f $file
	cleanup || error "stopping systems failed"
}
run_test 61 "large xattr"

test_62() {
	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi
	[[ "$MDS1_VERSION" -ge $(version_code 2.2.51) ]] ||
		skip "Need MDS version at least 2.2.51"

	# MRP-118
	local mdsdev=$(mdsdevname 1)
	local ostdev=$(ostdevname 1)

	echo "disable journal for mds"
	do_facet mds1 $TUNE2FS -O ^has_journal $mdsdev || error "tune2fs failed"
	start_mds && error "MDT start should fail"
	echo "disable journal for ost"
	do_facet ost1 $TUNE2FS -O ^has_journal $ostdev || error "tune2fs failed"
	start_ost && error "OST start should fail"
	cleanup || error "cleanup failed with rc $?"
	reformat_and_config
}
run_test 62 "start with disabled journal"

test_63() {
	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi

	do_rpc_nodes $(facet_active_host $SINGLEMDS) load_module ldiskfs
	local inode_slab=$(do_facet $SINGLEMDS "cat /proc/slabinfo" |
			   awk '/ldiskfs_inode_cache/ { print $5 / $6 }')
	if [ -z "$inode_slab" ]; then
		skip "ldiskfs module has not been loaded"
	fi

	if grep -q "CONFIG_DEBUG_LOCK_ALLOC=y" /boot/config-$(uname -r); then
		skip "test is not compatible with CONFIG_DEBUG_LOCK_ALLOC=y"
	fi

	echo "$inode_slab ldiskfs inodes per page"
	[ "${inode_slab%.*}" -ge "3" ] && return 0

	# If kmalloc-128 is also 1 per page - this is a debug kernel
	# and so this is not an error.
	local kmalloc128=$(do_facet $SINGLEMDS "cat /proc/slabinfo" |
			   awk '/^(dma-kmalloc|size)-128 / { print $5 / $6 }')
	# 32 128-byte chunks in 4k
	[ "${kmalloc128%.*}" -lt "32" ] ||
		error "ldiskfs inode too big, only $inode_slab objs/page, " \
		      "kmalloc128 = $kmalloc128 objs/page"
}
run_test 63 "Verify each page can at least hold 3 ldiskfs inodes"

test_64() {
	start_mds || error "unable to start MDS"
	start_ost || error "Unable to start OST1"
	start_ost2 || error "Unable to start second ost"
	mount_client $MOUNT || error "Unable to mount client"
	stop_ost2 || error "Unable to stop second ost"
	echo "$LFS df"
	$LFS df --lazy
	umount_client $MOUNT -f || error “unmount $MOUNT failed”
	cleanup_nocli || error "cleanup_nocli failed with $?"
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 64 "check lfs df --lazy "

test_65() { # LU-2237
	# Currently, the test is only valid for ldiskfs backend
	[ "$mds1_FSTYPE" != ldiskfs ] &&
		skip "ldiskfs only test"

	local devname=$(mdsdevname ${SINGLEMDS//mds/})
	local brpt=$(facet_mntpt brpt)
	local opts=""

	if ! do_facet $SINGLEMDS "test -b $devname"; then
		opts="-o loop"
	fi

	stop_mds || error "Unable to stop MDS"
	local obj=$(do_facet $SINGLEMDS \
		    "$DEBUGFS -c -R \\\"stat last_rcvd\\\" $devname" |
		    grep Inode)
	if [ -z "$obj" ]; then
		# The MDT may be just re-formatted, mount the MDT for the
		# first time to guarantee the "last_rcvd" file is there.
		start_mds || error "fail to mount the MDS for the first time"
		stop_mds || error "Unable to stop MDS"
	fi

	# remove the "last_rcvd" file
	do_facet $SINGLEMDS "mkdir -p $brpt"
	do_facet $SINGLEMDS \
		"mount -t $mds1_FSTYPE $opts $devname $brpt"
	do_facet $SINGLEMDS "rm -f ${brpt}/last_rcvd"
	do_facet $SINGLEMDS "$UMOUNT $brpt"

	# restart MDS, the "last_rcvd" file should be recreated.
	start_mds || error "fail to restart the MDS"
	stop_mds || error "Unable to stop MDS"
	obj=$(do_facet $SINGLEMDS \
	      "$DEBUGFS -c -R \\\"stat last_rcvd\\\" $devname" | grep Inode)
	[ -n "$obj" ] || error "fail to re-create the last_rcvd"
}
run_test 65 "re-create the lost last_rcvd file when server mount"

test_66() {
	[[ "$MGS_VERSION" -ge $(version_code 2.3.59) ]] ||
		skip "Need MGS version at least 2.3.59"

	setup
	local OST1_NID=$(do_facet ost1 $LCTL list_nids | head -1)
	local MDS_NID=$(do_facet $SINGLEMDS $LCTL list_nids | head -1)

	# add EXCLUDE records to config log, they are not to be
	# removed by lctl replace_nids
	set_conf_param_and_check mds					\
	    "$LCTL get_param -n osc.$FSNAME-OST0000-osc-MDT0000.active"	\
	    "$FSNAME-OST0000.osc.active"				\
	    "0"

	echo "replace_nids should fail if MDS, OSTs and clients are UP"
	do_facet mgs $LCTL replace_nids $FSNAME-OST0000 $OST1_NID &&
		error "replace_nids fail"

	umount_client $MOUNT || error "unmounting client failed"
	echo "replace_nids should fail if MDS and OSTs are UP"
	do_facet mgs $LCTL replace_nids $FSNAME-OST0000 $OST1_NID &&
		error "replace_nids fail"

	stop_ost || error "Unable to stop OST1"
	echo "replace_nids should fail if MDS is UP"
	do_facet mgs $LCTL replace_nids $FSNAME-OST0000 $OST1_NID &&
		error "replace_nids fail"

	stop_mds || error "stopping mds failed"

	if combined_mgs_mds; then
		start_mdt 1 "-o nosvc" ||
			error "starting mds with nosvc option failed"
	fi

	echo "command should accept two parameters"
	do_facet mgs $LCTL replace_nids $FSNAME-OST0000 &&
		error "command should accept two params"

	echo "correct device name should be passed"
	do_facet mgs $LCTL replace_nids $FSNAME-WRONG0000 $OST1_NID &&
		error "wrong devname"

	echo "wrong nids list should not destroy the system"
	do_facet mgs $LCTL replace_nids $FSNAME-OST0000 "wrong nids list" &&
		error "wrong parse"
	do_facet mgs $LCTL replace_nids $FSNAME-OST0000 "asdfasdf, asdfadf" &&
		error "wrong parse"

	echo "replace OST nid"
	do_facet mgs $LCTL replace_nids $FSNAME-OST0000 $OST1_NID ||
		error "replace nids failed"

	echo "command should accept two parameters"
	do_facet mgs $LCTL replace_nids $FSNAME-MDT0000 &&
		error "command should accept two params"

	echo "wrong nids list should not destroy the system"
	do_facet mgs $LCTL replace_nids $FSNAME-MDT0000 "wrong nids list" &&
		error "wrong parse"

	local FAKE_NIDS="192.168.0.112@tcp1,192.168.0.112@tcp2"
	local FAKE_FAILOVER="192.168.0.113@tcp1,192.168.0.113@tcp2"
	local NIDS_AND_FAILOVER="$MDS_NID,$FAKE_NIDS:$FAKE_FAILOVER"
	echo "set NIDs with failover"
	do_facet mgs $LCTL replace_nids $FSNAME-MDT0000 $NIDS_AND_FAILOVER ||
		error "replace nids failed"


	echo "replace MDS nid"
	do_facet mgs $LCTL replace_nids $FSNAME-MDT0000 $MDS_NID ||
		error "replace nids failed"

	if ! combined_mgs_mds ; then
		stop_mgs
	else
		stop_mds || error "Unable to stop MDS"
	fi

	start_mgsmds || error "start mgsmds failed"
	set_conf_param_and_check mds					\
	    "$LCTL get_param -n osc.$FSNAME-OST0000-osc-MDT0000.active"	\
	    "$FSNAME-OST0000.osc.active"				\
	    "1"
	start_ost || error "unable to start OST"
	mount_client $MOUNT || error "mount client failed"

	check_mount || error "error after nid replace"
	cleanup || error "cleanup failed"
	reformat_and_config
}
run_test 66 "replace nids"

test_67() { #LU-2950
	local legacy="$TMP/legacy_lnet_config"
	local new="$TMP/new_routes_test"
	local out="$TMP/config_out_file"
	local verify="$TMP/conv_verify"
	local verify_conf="$TMP/conf_verify"

	# Create the legacy file that will be run through the
	# lustre_routes_conversion script
	cat <<- LEGACY_LNET_CONFIG > $legacy
		tcp1 23 192.168.213.1@tcp:1; tcp5 34 193.30.4.3@tcp:4;
		tcp2 54 10.1.3.2@tcp;
		tcp3 10.3.4.3@tcp:3;
		tcp4 10.3.3.4@tcp;
	LEGACY_LNET_CONFIG

	# Create the verification file to verify the output of
	# lustre_routes_conversion script against.
	cat <<- VERIFY_LNET_CONFIG > $verify
		tcp1: { gateway: 192.168.213.1@tcp, hop: 23, priority: 1 }
		tcp5: { gateway: 193.30.4.3@tcp, hop: 34, priority: 4 }
		tcp2: { gateway: 10.1.3.2@tcp, hop: 54 }
		tcp3: { gateway: 10.3.4.3@tcp, priority: 3 }
		tcp4: { gateway: 10.3.3.4@tcp }
	VERIFY_LNET_CONFIG

	# Create the verification file to verify the output of
	# lustre_routes_config script against
	cat <<- VERIFY_LNET_CONFIG > $verify_conf
		lctl --net tcp1 add_route 192.168.213.1@tcp 23 1
		lctl --net tcp5 add_route 193.30.4.3@tcp 34 4
		lctl --net tcp2 add_route 10.1.3.2@tcp 54 4
		lctl --net tcp3 add_route 10.3.4.3@tcp 1 3
		lctl --net tcp4 add_route 10.3.3.4@tcp 1 3
	VERIFY_LNET_CONFIG

	$LUSTRE_ROUTES_CONVERSION $legacy $new > /dev/null
	if [ -f $new ]; then
		# verify the conversion output
		cmp -s $new $verify > /dev/null
		if [ $? -eq 1 ]; then
			error "routes conversion failed"
		fi

		lustre_routes_config --dry-run --verbose $new > $out
		# check that the script succeeded
		cmp -s $out $verify_conf > /dev/null
		if [ $? -eq 1 ]; then
			error "routes config failed"
		fi
	else
		error "routes conversion test failed"
	fi
	# remove generated files
	rm -f $new $legacy $verify $verify_conf $out
}
run_test 67 "test routes conversion and configuration"

test_68() {
	local fid
	local seq
	local START
	local END

	[ "$MDS1_VERSION" -ge $(version_code 2.4.53) ] ||
		skip "Need MDS version at least 2.4.53"

	umount_client $MOUNT || error "umount client failed"

	start_mgsmds
	start_ost

	# START-END - the sequences we'll be reserving
	START=$(do_facet $SINGLEMDS \
		$LCTL get_param -n seq.ctl*.space | awk -F'[[ ]' '{print $2}')
	END=$((START + (1 << 30)))
	do_facet $SINGLEMDS \
		$LCTL set_param seq.ctl*.fldb="[$START-$END\):0:mdt"

	# reset the sequences MDT0000 has already assigned
	do_facet $SINGLEMDS \
		$LCTL set_param seq.srv*MDT0000.space=clear

	# remount to let the client allocate new sequence
	mount_client $MOUNT || error "mount client failed"

	touch $DIR/$tfile || error "touch $DIR/$tfile failed"
	do_facet $SINGLEMDS \
		$LCTL get_param seq.srv*MDT0000.space
	$LFS path2fid $DIR/$tfile

	local old_ifs="$IFS"
	IFS='[:]'
	fid=($($LFS path2fid $DIR/$tfile))
	IFS="$old_ifs"
	let seq=${fid[1]}

	if [[ $seq < $END ]]; then
		error "used reserved sequence $seq?"
	fi
	cleanup || error "cleanup failed with $?"
}
run_test 68 "be able to reserve specific sequences in FLDB"

# Test 69: is about the total number of objects ever created on an OST.
# so that when it is reformatted the normal MDS->OST orphan recovery won't
# just "precreate" the missing objects. In the past it might try to recreate
# millions of objects after an OST was reformatted
test_69() {
	[[ "$MDS1_VERSION" -lt $(version_code 2.4.2) ]] &&
		skip "Need MDS version at least 2.4.2"

	[[ "$MDS1_VERSION" -ge $(version_code 2.4.50) ]] &&
	[[ "$MDS1_VERSION" -lt $(version_code 2.5.0) ]] &&
		skip "Need MDS version at least 2.5.0"

	setup
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	# use OST0000 since it probably has the most creations
	local OSTNAME=$(ostname_from_index 0)
	local mdtosc_proc1=$(get_mdtosc_proc_path mds1 $OSTNAME)
	local last_id=$(do_facet mds1 $LCTL get_param -n \
			osp.$mdtosc_proc1.prealloc_last_id)

	# Want to have OST LAST_ID over 5 * OST_MAX_PRECREATE to
	# verify that the LAST_ID recovery is working properly. If
	# not, then the OST will refuse to allow the MDS connect
	# because the LAST_ID value is too different from the MDS
	#define OST_MAX_PRECREATE=20000
	local ost_max_pre=20000
	local num_create=$(( ost_max_pre * 5 + 1 - last_id))

	# If the LAST_ID is already over 5 * OST_MAX_PRECREATE, we don't
	# need to create any files. So, skip this section.
	if [ $num_create -gt 0 ]; then
		# Check the number of inodes available on OST0
		local files=0
		local ifree=$($LFS df -i $MOUNT |
			awk '/OST0000/ { print $4 }'; exit ${PIPESTATUS[0]})
		log "On OST0, $ifree inodes available. Want $num_create. rc=$?"

		$LFS setstripe -i 0 $DIR/$tdir ||
			error "$LFS setstripe -i 0 $DIR/$tdir failed"
		if [ $ifree -lt 10000 ]; then
			files=$(( ifree - 50 ))
		else
			files=10000
		fi

		local j=$((num_create / files + 1))
		for i in $(seq 1 $j); do
			createmany -o $DIR/$tdir/$tfile-$i- $files ||
				error "createmany fail create $files files: $?"
			unlinkmany $DIR/$tdir/$tfile-$i- $files ||
				error "unlinkmany failed unlink $files files"
		done
	fi

	# delete all of the files with objects on OST0 so the
	# filesystem is not inconsistent later on
	$LFS find $MOUNT --ost 0 -print0 | xargs -0 rm

	umount_client $MOUNT || error "umount client failed"
	stop_ost || error "OST0 stop failure"
	add ost1 $(mkfs_opts ost1 $(ostdevname 1)) --reformat --replace \
		$(ostdevname 1) $(ostvdevname 1) ||
		error "reformat and replace $ostdev failed"
	start_ost || error "OST0 restart failure"
	wait_osc_import_state mds ost FULL

	mount_client $MOUNT || error "mount client failed"
	touch $DIR/$tdir/$tfile-last || error "create file after reformat"
	local idx=$($LFS getstripe -i $DIR/$tdir/$tfile-last)
	[ $idx -ne 0 ] && error "$DIR/$tdir/$tfile-last on $idx not 0" || true

	local iused=$($LFS df -i $MOUNT |
		awk '/OST0000/ { print $3 }'; exit ${PIPESTATUS[0]})
	log "On OST0, $iused used inodes rc=$?"
	[ $iused -ge $((ost_max_pre/2 + 1000)) ] &&
		error "OST replacement created too many inodes; $iused"
	cleanup || error "cleanup failed with $?"
}
run_test 69 "replace an OST with the same index"

test_70a() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	local MDTIDX=1

	cleanup || error "cleanup failed with $?"

	start_mdt 1 || error "MDT0 start fail"

	start_ost || error "OST0 start fail"
	for num in $(seq 2 $MDSCOUNT); do
		start_mdt $num || return
	done

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "create $DIR/$tdir failed"

	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir fail"

	rm -rf $DIR/$tdir || error "delete dir fail"
	cleanup || error "cleanup failed with $?"
}
run_test 70a "start MDT0, then OST, then MDT1"

test_70b() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	local MDTIDX=1

	start_ost || error "OST0 start fail"

	start_mds || error "MDS start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "create $DIR/$tdir failed"

	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir fail"

	rm -rf $DIR/$tdir || error "delete dir fail"

	cleanup || error "cleanup failed with $?"
}
run_test 70b "start OST, MDT1, MDT0"

test_70c() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	local MDTIDX=1

	start_mds || error "MDS start fail"
	start_ost || error "OST0 start fail"

	mount_client $MOUNT || error "mount client fails"
	stop_mdt 1 || error "MDT1 start fail"

	local mdc_for_mdt1=$($LCTL dl | grep MDT0000-mdc | awk '{print $4}')
	echo "deactivate $mdc_for_mdt1"
	$LCTL --device $mdc_for_mdt1 deactivate ||
		error "set $mdc_for_mdt1 deactivate failed"

	mkdir $DIR/$tdir && error "mkdir succeed"

	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir &&
		error "create remote dir succeed"

	cleanup || error "cleanup failed with $?"
}
run_test 70c "stop MDT0, mkdir fail, create remote dir fail"

test_70d() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	local MDTIDX=1

	start_mds || error "MDS start fail"
	start_ost || error "OST0 start fail"

	mount_client $MOUNT || error "mount client fails"

	stop_mdt 2 || error "MDT1 start fail"

	local mdc_for_mdt2=$($LCTL dl | grep MDT0001-mdc |
			     awk '{print $4}')
	echo "deactivate $mdc_for_mdt2"
	$LCTL --device $mdc_for_mdt2 deactivate ||
		error "set $mdc_for_mdt2 deactivate failed"

	mkdir $DIR/$tdir || error "mkdir fail"
	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir &&
		error "create remote dir succeed"

	rm -rf $DIR/$tdir || error "delete dir fail"

	cleanup || error "cleanup failed with $?"
}
run_test 70d "stop MDT1, mkdir succeed, create remote dir fail"

test_70e() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"

	[ "$MDS1_VERSION" -ge $(version_code 2.7.62) ] ||
		skip "Need MDS version at least 2.7.62"

	reformat || error "reformat failed with $?"

	load_modules

	local mdsdev=$(mdsdevname 1)
	local ostdev=$(ostdevname 1)
	local mdsvdev=$(mdsvdevname 1)
	local ostvdev=$(ostvdevname 1)
	local opts_mds="$(mkfs_opts mds1 $mdsdev) --reformat $mdsdev $mdsvdev"
	local opts_ost="$(mkfs_opts ost1 $ostdev) --reformat $ostdev $ostvdev"

	if ! combined_mgs_mds ; then
		start_mgs
	fi

	add mds1 $opts_mds || error "add mds1 failed"
	start_mdt 1 || error "start mdt1 failed"
	add ost1 $opts_ost || error "add ost1 failed"
	start_ost || error "start ost failed"
	mount_client $MOUNT > /dev/null || error "mount client $MOUNT failed"

	local soc=$(do_facet mds1 "$LCTL get_param -n \
		    mdt.*MDT0000.sync_lock_cancel")
	[ $soc == "never" ] || error "SoC enabled on single MDS"

	for i in $(seq 2 $MDSCOUNT); do
		mdsdev=$(mdsdevname $i)
		mdsvdev=$(mdsvdevname $i)
		opts_mds="$(mkfs_opts mds$i $mdsdev) --reformat $mdsdev \
			  $mdsvdev"
		add mds$i $opts_mds || error "add mds$i failed"
		start_mdt $i || error "start mdt$i fail"
	done

	wait_dne_interconnect

	for i in $(seq $MDSCOUNT); do
		soc=$(do_facet mds$i "$LCTL get_param -n \
			mdt.*MDT000$((i - 1)).sync_lock_cancel")
		[ $soc == "blocking" ] || error "SoC not enabled on DNE"
	done

	for i in $(seq 2 $MDSCOUNT); do
		stop_mdt $i || error "stop mdt$i fail"
	done
	soc=$(do_facet mds1 "$LCTL get_param -n \
		mdt.*MDT0000.sync_lock_cancel")
	[ $soc == "never" ] || error "SoC enabled on single MDS"
	umount_client $MOUNT -f > /dev/null

	cleanup || error "cleanup failed with $?"
}
run_test 70e "Sync-on-Cancel will be enabled by default on DNE"

test_71a() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	if combined_mgs_mds; then
		skip "needs separate MGS/MDT"
	fi
	local MDTIDX=1

	start_mdt 1 || error "MDT0 start fail"
	start_ost || error "OST0 start fail"
	for num in $(seq 2 $MDSCOUNT); do
		start_mdt $num || return
	done

	start_ost2 || error "OST1 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "mkdir fail"
	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir succeed"

	mcreate $DIR/$tdir/remote_dir/$tfile || error "create file failed"
	rm -rf $DIR/$tdir || error "delete dir fail"

	umount_client $MOUNT || error "umount_client failed"
	stop_mds || error "MDS stop fail"
	stop_ost || error "OST0 stop fail"
	stop_ost2 || error "OST1 stop fail"
}
run_test 71a "start MDT0 OST0, MDT1, OST1"

test_71b() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	if combined_mgs_mds; then
		skip "needs separate MGS/MDT"
	fi
	local MDTIDX=1

	for num in $(seq 2 $MDSCOUNT); do
		start_mdt $num || return
	done
	start_ost || error "OST0 start fail"
	start_mdt 1 || error "MDT0 start fail"
	start_ost2 || error "OST1 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "mkdir fail"
	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir succeed"

	mcreate $DIR/$tdir/remote_dir/$tfile || error "create file failed"
	rm -rf $DIR/$tdir || error "delete dir fail"

	umount_client $MOUNT || error "umount_client failed"
	stop_mds || error "MDT0 stop fail"
	stop_ost || error "OST0 stop fail"
	stop_ost2 || error "OST1 stop fail"
}
run_test 71b "start MDT1, OST0, MDT0, OST1"

test_71c() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	combined_mgs_mds && skip "needs separate MGS/MDT"

	local MDTIDX=1

	start_ost || error "OST0 start fail"
	start_ost2 || error "OST1 start fail"
	for num in $(seq 2 $MDSCOUNT); do
		start_mdt $num || return
	done
	start_mdt 1 || error "MDT0 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "mkdir fail"
	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir succeed"

	mcreate $DIR/$tdir/remote_dir/$tfile || error "create file failed"
	rm -rf $DIR/$tdir || error "delete dir fail"

	umount_client $MOUNT || error "umount_client failed"
	stop_mds || error "MDS stop fail"
	stop_ost || error "OST0 stop fail"
	stop_ost2 || error "OST1 stop fail"

}
run_test 71c "start OST0, OST1, MDT1, MDT0"

test_71d() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	combined_mgs_mds && skip "needs separate MGS/MDT"

	local MDTIDX=1

	start_ost || error "OST0 start fail"
	for num in $(seq 2 $MDSCOUNT); do
		start_mdt $num || return
	done
	start_mdt 1 || error "MDT0 start fail"
	start_ost2 || error "OST1 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "mkdir fail"
	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
			error "create remote dir succeed"

	mcreate $DIR/$tdir/remote_dir/$tfile || error "create file failed"
	rm -rf $DIR/$tdir || error "delete dir fail"

	umount_client $MOUNT || error "umount_client failed"
	stop_mds || error "MDS stop fail"
	stop_ost || error "OST0 stop fail"
	stop_ost2 || error "OST1 stop fail"

}
run_test 71d "start OST0, MDT1, MDT0, OST1"

test_71e() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	combined_mgs_mds && skip "needs separate MGS/MDT"

	local MDTIDX=1

	start_ost || error "OST0 start fail"
	for num in $(seq 2 $MDSCOUNT); do
		start_mdt $num || return
	done
	start_ost2 || error "OST1 start fail"
	start_mdt 1 || error "MDT0 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "mkdir fail"
	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir succeed"

	mcreate $DIR/$tdir/remote_dir/$tfile || error "create file failed"
	rm -rf $DIR/$tdir || error "delete dir fail"

	umount_client $MOUNT || error "umount_client failed"
	stop_mds || error "MDS stop fail"
	stop_ost || error "OST0 stop fail"
	stop_ost2 || error "OST1 stop fail"

}
run_test 71e "start OST0, MDT1, OST1, MDT0"

test_72() { #LU-2634
	[ "$mds1_FSTYPE" != ldiskfs ] &&
		skip "ldiskfs only test"

	local mdsdev=$(mdsdevname 1)
	local ostdev=$(ostdevname 1)
	local cmd="$E2FSCK -fnvd $mdsdev"
	local fn=3
	local add_options

	cleanup
	load_modules

	if combined_mgs_mds; then
		add_options='--reformat'
	else
		add_options='--reformat --replace'
	fi

	#tune MDT with "-O extents"

	for num in $(seq $MDSCOUNT); do
		add mds${num} $(mkfs_opts mds$num $(mdsdevname $num)) \
			$add_options $(mdsdevname $num) $(mdsvdevname $num) ||
			error "add mds $num failed"
		do_facet mds${num} "$TUNE2FS -O extents $(mdsdevname $num)" ||
			error "$TUNE2FS failed on mds${num}"
	done

	add ost1 $(mkfs_opts ost1 $ostdev) $add_options $ostdev ||
		error "add $ostdev failed"
	start_mds || error "start mds failed"
	start_ost || error "start ost failed"
	mount_client $MOUNT || error "mount client failed"

	#create some short symlinks
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	createmany -o $DIR/$tdir/$tfile-%d $fn
	echo "create $fn short symlinks"
	for i in $(seq -w 1 $fn); do
		ln -s $DIR/$tdir/$tfile-$i $MOUNT/$tfile-$i
	done
	ls -al $MOUNT

	#umount
	umount_client $MOUNT || error "umount client failed"
	stop_mds || error "stop mds failed"
	stop_ost || error "stop ost failed"

	#run e2fsck
	run_e2fsck $(facet_active_host $SINGLEMDS) $mdsdev "-n"
}
run_test 72 "test fast symlink with extents flag enabled"

test_73() { #LU-3006
	[ "$ost1_FSTYPE" == zfs ] && import_zpool ost1
	do_facet ost1 "$TUNEFS --failnode=1.2.3.4@$NETTYPE $(ostdevname 1)" ||
		error "1st tunefs failed"
	start_mgsmds || error "start mds failed"
	start_ost || error "start ost failed"
	mount_client $MOUNT || error "mount client failed"
	$LCTL get_param -n osc.*OST0000-osc-[^M]*.import | grep failover_nids |
		grep 1.2.3.4@$NETTYPE || error "failover nids haven't changed"
	umount_client $MOUNT || error "umount client failed"
	stop_ost
	stop_mds
}
run_test 73 "failnode to update from mountdata properly"

test_75() { # LU-2374
	[[ "$MDS1_VERSION" -lt $(version_code 2.4.1) ]] &&
		skip "Need MDS version at least 2.4.1"

	local index=0
	local opts_mds="$(mkfs_opts mds1 $(mdsdevname 1)) \
		--replace --reformat $(mdsdevname 1) $(mdsvdevname 1)"
	local opts_ost="$(mkfs_opts ost1 $(ostdevname 1)) \
		--replace --reformat $(ostdevname 1) $(ostvdevname 1)"

	#check with default parameters
	add mds1 $opts_mds || error "add mds1 failed for default params"
	add ost1 $opts_ost || error "add ost1 failed for default params"

	opts_mds=$(echo $opts_mds | sed -e "s/--mdt//")
	opts_mds=$(echo $opts_mds |
		   sed -e "s/--index=$index/--index=$index --mdt/")
	opts_ost=$(echo $opts_ost | sed -e "s/--ost//")
	opts_ost=$(echo $opts_ost |
		   sed -e "s/--index=$index/--index=$index --ost/")

	add mds1 $opts_mds || error "add mds1 failed for new params"
	add ost1 $opts_ost || error "add ost1 failed for new params"

	reformat_and_config
	return 0
}
run_test 75 "The order of --index should be irrelevant"

test_76a() {
	[[ "$MGS_VERSION" -ge $(version_code 2.4.52) ]] ||
		skip "Need MDS version at least 2.4.52"

	setup
	local MDMB_PARAM="osc.*.max_dirty_mb"
	echo "Change MGS params"
	local MAX_DIRTY_MB=$($LCTL get_param -n $MDMB_PARAM |
		head -1)
	echo "max_dirty_mb: $MAX_DIRTY_MB"
	local NEW_MAX_DIRTY_MB=$((MAX_DIRTY_MB - 10))
	echo "new_max_dirty_mb: $NEW_MAX_DIRTY_MB"
	do_facet mgs $LCTL set_param -P $MDMB_PARAM=$NEW_MAX_DIRTY_MB
	wait_update $HOSTNAME "$LCTL get_param -n $MDMB_PARAM |
		head -1" $NEW_MAX_DIRTY_MB
	MAX_DIRTY_MB=$($LCTL get_param -n $MDMB_PARAM | head -1)
	echo "$MAX_DIRTY_MB"
	[ $MAX_DIRTY_MB = $NEW_MAX_DIRTY_MB ] ||
		error "error while apply max_dirty_mb"

	echo "Check the value is stored after remount"
	stopall
	setupall
	wait_update $HOSTNAME "$LCTL get_param -n $MDMB_PARAM |
		head -1" $NEW_MAX_DIRTY_MB
	MAX_DIRTY_MB=$($LCTL get_param -n $MDMB_PARAM | head -1)
	[ $MAX_DIRTY_MB = $NEW_MAX_DIRTY_MB ] ||
		error "max_dirty_mb is not saved after remount"

	echo "Change OST params"
	CLIENT_PARAM="obdfilter.*.client_cache_count"
	local CLIENT_CACHE_COUNT
	CLIENT_CACHE_COUNT=$(do_facet ost1 $LCTL get_param -n $CLIENT_PARAM |
		head -1)
	echo "client_cache_count: $CLIENT_CACHE_COUNT"
	NEW_CLIENT_CACHE_COUNT=$((CLIENT_CACHE_COUNT+CLIENT_CACHE_COUNT))
	echo "new_client_cache_count: $NEW_CLIENT_CACHE_COUNT"
	do_facet mgs $LCTL set_param -P $CLIENT_PARAM=$NEW_CLIENT_CACHE_COUNT
	wait_update $(facet_host ost1) "$LCTL get_param -n $CLIENT_PARAM |
		head -1" $NEW_CLIENT_CACHE_COUNT
	CLIENT_CACHE_COUNT=$(do_facet ost1 $LCTL get_param -n $CLIENT_PARAM |
		head -1)
	echo "$CLIENT_CACHE_COUNT"
	[ $CLIENT_CACHE_COUNT = $NEW_CLIENT_CACHE_COUNT ] ||
		error "error while apply client_cache_count"

	echo "Check the value is stored after remount"
	stopall
	setupall
	wait_update $(facet_host ost1) "$LCTL get_param -n $CLIENT_PARAM |
		head -1" $NEW_CLIENT_CACHE_COUNT
	CLIENT_CACHE_COUNT=$(do_facet ost1 $LCTL get_param -n $CLIENT_PARAM |
		head -1)
	echo "$CLIENT_CACHE_COUNT"
	[ $CLIENT_CACHE_COUNT = $NEW_CLIENT_CACHE_COUNT ] ||
		error "client_cache_count is not saved after remount"
	stopall
}
run_test 76a "set permanent params with lctl across mounts"

test_76b() { # LU-4783
	[[ "$MGS_VERSION" -ge $(version_code 2.5.57) ]] ||
		skip "Need MGS version at least 2.5.57"
	stopall
	setupall
	do_facet mgs $LCTL get_param mgs.MGS.live.params ||
		error "start params log failed"
	stopall
}
run_test 76b "verify params log setup correctly"

test_76c() {
	[[ "$MGS_VERSION" -ge $(version_code 2.8.54) ]] ||
		skip "Need MDS version at least 2.4.52"
	setupall
	local MASK_PARAM="mdd.*.changelog_mask"
	echo "Change changelog_mask"
	do_facet mgs $LCTL set_param -P $MASK_PARAM=-CLOSE ||
		error "Can't change changlog_mask"
	wait_update $(facet_host mds) "$LCTL get_param -n $MASK_PARAM |
		grep 'CLOSE'" ""

	echo "Check the value is stored after mds remount"
	stop_mds || error "Failed to stop MDS"
	start_mds || error "Failed to start MDS"
	local CHANGELOG_MASK=$(do_facet mgs $LCTL get_param -n $MASK_PARAM)
	echo $CHANGELOG_MASK | grep CLOSE > /dev/null &&
		error "changelog_mask is not changed"

	stopall
}
run_test 76c "verify changelog_mask is applied with lctl set_param -P"

test_76d() { #LU-9399
	setupall

	local xattr_cache="llite.*.xattr_cache"
	local cmd="$LCTL get_param -n $xattr_cache | head -1"
	local new=$((($(eval $cmd) + 1) % 2))

	echo "lctl set_param -P llite.*.xattr_cache=$new"
	do_facet mgs $LCTL set_param -P $xattr_cache=$new ||
		error "Can't change xattr_cache"
	wait_update $HOSTNAME "$cmd" "$new"

	echo "Check $xattr_cache on client $MOUNT"
	umount_client $MOUNT || error "umount $MOUNT failed"
	mount_client $MOUNT || error "mount $MOUNT failed"
	[ $(eval $cmd) -eq $new ] ||
		error "$xattr_cache != $new on client $MOUNT"

	echo "Check $xattr_cache on the new client $MOUNT2"
	mount_client $MOUNT2 || error "mount $MOUNT2 failed"
	[ $(eval $cmd) -eq $new ] ||
		error "$xattr_cache != $new on client $MOUNT2"
	umount_client $MOUNT2 || error "umount $MOUNT2 failed"

	stopall
}
run_test 76d "verify llite.*.xattr_cache can be set by 'lctl set_param -P' correctly"

test_77() { # LU-3445
	[[ "$MDS1_VERSION" -ge $(version_code 2.8.55) ]] ||
		skip "Need MDS version 2.8.55+ "

	if [[ -z "$fs2ost_DEV" || -z "$fs2mds_DEV" ]]; then
		is_blkdev $SINGLEMDS $(mdsdevname ${SINGLEMDS//mds/}) &&
		skip_env "mixed loopback and real device not working"
	fi

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2ostdev=$(ostdevname 1_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)
	local fs2ostvdev=$(ostvdevname 1_2)
	local fsname=test1234
	local mgsnid
	local failnid="$(h2nettype 1.2.3.4),$(h2nettype 4.3.2.1)"

	combined_mgs_mds || stop_mgs || error "stopping MGS service failed"

	add fs2mds $(mkfs_opts mds1 $fs2mdsdev) --mgs --fsname=$fsname \
		--reformat $fs2mdsdev $fs2mdsvdev || error "add fs2mds failed"
	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS && trap cleanup_fs2 EXIT INT ||
		error "start fs2mds failed"

	mgsnid=$(do_facet fs2mds $LCTL list_nids | xargs | tr ' ' ,)
	mgsnid="0.0.0.0@tcp,$mgsnid,$mgsnid:$mgsnid"

	add fs2ost --mgsnode=$mgsnid $(mkfs_opts ost1 $fs2ostdev) \
		--failnode=$failnid --fsname=$fsname \
		--reformat $fs2ostdev $fs2ostvdev ||
			error "add fs2ost failed"
	start fs2ost $fs2ostdev $OST_MOUNT_OPTS || error "start fs2ost failed"

	mkdir -p $MOUNT2 || error "mkdir $MOUNT2 failed"
	$MOUNT_CMD $mgsnid:/$fsname $MOUNT2 || error "mount $MOUNT2 failed"
	DIR=$MOUNT2 MOUNT=$MOUNT2 check_mount || error "check $MOUNT2 failed"
	cleanup_fs2
}
run_test 77 "comma-separated MGS NIDs and failover node NIDs"

test_78() {
	[[ "$mds1_FSTYPE" != ldiskfs ||
	   "$ost1_FSTYPE" != ldiskfs ]] &&
		skip "ldiskfs only test"

	# reformat the Lustre filesystem with a smaller size
	local saved_MDSCOUNT=$MDSCOUNT
	local saved_MDSSIZE=$MDSSIZE
	local saved_OSTCOUNT=$OSTCOUNT
	local saved_OSTSIZE=$OSTSIZE
	MDSCOUNT=1
	OSTCOUNT=1
	MDSSIZE=$((MDSSIZE - 20000))
	OSTSIZE=$((OSTSIZE - 20000))
	reformat || error "(1) reformat Lustre filesystem failed"
	MDSSIZE=$saved_MDSSIZE
	OSTSIZE=$saved_OSTSIZE

	# mount the Lustre filesystem
	setup_noconfig || error "(2) setup Lustre filesystem failed"

	# create some files
	log "create test files"
	local i
	local file
	local num_files=100

	mkdir $MOUNT/$tdir || error "(3) mkdir $MOUNT/$tdir failed"
	$LFS df; $LFS df -i
	for i in $(seq $num_files); do
		file=$MOUNT/$tdir/$tfile-$i
		dd if=/dev/urandom of=$file count=1 bs=1M || {
			$LCTL get_param osc.*.cur*grant*
			$LFS df; $LFS df -i;
			# stop creating files if there is no more space
			if [ ! -e $file ]; then
				num_files=$((i - 1))
				break
			fi

			$LFS getstripe -v $file
			local ost_idx=$(LFS getstripe -i $file)
			do_facet ost$((ost_idx + 1)) \
				$LCTL get_param obdfilter.*.*grant*
			error "(4) create $file failed"
		}
	done

	# unmount the Lustre filesystem
	cleanup || error "(5) cleanup Lustre filesystem failed"

	# run e2fsck on the MDT and OST devices
	local mds_host=$(facet_active_host $SINGLEMDS)
	local ost_host=$(facet_active_host ost1)
	local mds_dev=$(mdsdevname ${SINGLEMDS//mds/})
	local ost_dev=$(ostdevname 1)

	run_e2fsck $mds_host $mds_dev "-y"
	run_e2fsck $ost_host $ost_dev "-y"

	# get the original block count of the MDT and OST filesystems
	local mds_orig_blks=$(get_block_count $SINGLEMDS $mds_dev)
	local ost_orig_blks=$(get_block_count ost1 $ost_dev)

	# expand the MDT and OST filesystems to the device size
	run_resize2fs $SINGLEMDS $mds_dev "" || error "expand $SINGLEMDS failed"
	run_resize2fs ost1 $ost_dev "" || error "expand ost1 failed"

	# run e2fsck on the MDT and OST devices again
	run_e2fsck $mds_host $mds_dev "-y"
	run_e2fsck $ost_host $ost_dev "-y"

	# mount the Lustre filesystem
	setup

	# check the files
	log "check files after expanding the MDT and OST filesystems"
	for i in $(seq $num_files); do
		file=$MOUNT/$tdir/$tfile-$i
		$CHECKSTAT -t file -s 1048576 $file ||
			error "(6) checkstat $file failed"
	done

	# create more files
	log "create more files after expanding the MDT and OST filesystems"
	for i in $(seq $((num_files + 1)) $((num_files + 10))); do
		file=$MOUNT/$tdir/$tfile-$i
		dd if=/dev/urandom of=$file count=1 bs=1M ||
			error "(7) create $file failed"
	done

	# unmount the Lustre filesystem
	cleanup || error "(8) cleanup Lustre filesystem failed"

	# run e2fsck on the MDT and OST devices
	run_e2fsck $mds_host $mds_dev "-y"
	run_e2fsck $ost_host $ost_dev "-y"

	# get the maximum block count of the MDT and OST filesystems
	local mds_max_blks=$(get_block_count $SINGLEMDS $mds_dev)
	local ost_max_blks=$(get_block_count ost1 $ost_dev)

	# get the minimum block count of the MDT and OST filesystems
	local mds_min_blks=$(run_resize2fs $SINGLEMDS $mds_dev "" "-P" 2>&1 |
				grep minimum | sed -e 's/^.*filesystem: //g')
	local ost_min_blks=$(run_resize2fs ost1 $ost_dev "" "-P" 2>&1 |
				grep minimum | sed -e 's/^.*filesystem: //g')

	# shrink the MDT and OST filesystems to a smaller size
	local shrunk=false
	local new_blks
	local base_blks
	if [[ $mds_max_blks -gt $mds_min_blks &&
	      $mds_max_blks -gt $mds_orig_blks ]]; then
		[[ $mds_orig_blks -gt $mds_min_blks ]] &&
			base_blks=$mds_orig_blks || base_blks=$mds_min_blks
		new_blks=$(( (mds_max_blks - base_blks) / 2 + base_blks ))
		run_resize2fs $SINGLEMDS $mds_dev $new_blks ||
			error "shrink $SINGLEMDS to $new_blks failed"
		shrunk=true
	fi

	if [[ $ost_max_blks -gt $ost_min_blks &&
	      $ost_max_blks -gt $ost_orig_blks ]]; then
		[[ $ost_orig_blks -gt $ost_min_blks ]] &&
			base_blks=$ost_orig_blks || base_blks=$ost_min_blks
		new_blks=$(( (ost_max_blks - base_blks) / 2 + base_blks ))
		run_resize2fs ost1 $ost_dev $new_blks ||
			error "shrink ost1 to $new_blks failed"
		shrunk=true
	fi

	# check whether the MDT or OST filesystem was shrunk or not
	if ! $shrunk; then
		combined_mgs_mds || stop_mgs || error "(9) stop mgs failed"
		reformat_and_config ||
			error "(10) reformat Lustre filesystem failed"
		return 0
	fi

	# run e2fsck on the MDT and OST devices again
	run_e2fsck $mds_host $mds_dev "-y"
	run_e2fsck $ost_host $ost_dev "-y"

	# mount the Lustre filesystem again
	setup

	# check the files
	log "check files after shrinking the MDT and OST filesystems"
	for i in $(seq $((num_files + 10))); do
		file=$MOUNT/$tdir/$tfile-$i
		$CHECKSTAT -t file -s 1048576 $file ||
			error "(11) checkstat $file failed"
	done

	# unmount and reformat the Lustre filesystem
	cleanup || error "(12) cleanup Lustre filesystem failed"
	combined_mgs_mds || stop_mgs || error "(13) stop mgs failed"

	MDSCOUNT=$saved_MDSCOUNT
	OSTCOUNT=$saved_OSTCOUNT
	reformat_and_config || error "(14) reformat Lustre filesystem failed"
}
run_test 78 "run resize2fs on MDT and OST filesystems"

test_79() { # LU-4227
	[[ "$MDS1_VERSION" -ge $(version_code 2.5.59) ]] ||
		skip "Need MDS version at least 2.5.59"

	local mdsdev1=$(mdsdevname 1)
	local mdsvdev1=$(mdsvdevname 1)
	local mdsdev2=$(mdsdevname 2)
	local mdsvdev2=$(mdsvdevname 2)
	local ostdev1=$(ostdevname 1)
	local ostvdev1=$(ostvdevname 1)
	local opts_mds1="$(mkfs_opts mds1 $mdsdev1) --reformat"
	local opts_mds2="$(mkfs_opts mds2 $mdsdev2) --reformat"
	local opts_ost1="$(mkfs_opts ost1 $ostdev1) --reformat"
	local mgsnode_opt

	# remove --mgs/--mgsnode from mkfs.lustre options
	opts_mds1=$(echo $opts_mds1 | sed -e "s/--mgs//")

	mgsnode_opt=$(echo $opts_mds2 |
		awk '{ for ( i = 1; i < NF; i++ )
			if ( $i ~ "--mgsnode" ) { print $i; break } }')
	[ -n "$mgsnode_opt" ] &&
		opts_mds2=$(echo $opts_mds2 | sed -e "s/$mgsnode_opt//")

	mgsnode_opt=$(echo $opts_ost1 |
		awk '{ for ( i = 1; i < NF; i++ )
			if ( $i ~ "--mgsnode" ) { print $i; break } }')
	[ -n "$mgsnode_opt" ] &&
		opts_ost1=$(echo $opts_ost1 | sed -e "s/$mgsnode_opt//")
	load_modules
	# -MGS, format a mdt without --mgs option
	add mds1 $opts_mds1 $mdsdev1 $mdsvdev1 &&
		error "Must specify --mgs when formatting mdt combined with mgs"

	# +MGS, format a mdt/ost without --mgsnode option
	add mds1 $(mkfs_opts mds1 $mdsdev1) --reformat $mdsdev1 $mdsvdev1 \
		> /dev/null || error "start mds1 failed"
	add mds2 $opts_mds2 $mdsdev2 $mdsvdev2 &&
		error "Must specify --mgsnode when formatting a mdt"
	add ost1 $opts_ost1 $ostdev1 $ostvdev2 &&
		error "Must specify --mgsnode when formatting an ost"

	reformat_and_config
}
run_test 79 "format MDT/OST without mgs option (should return errors)"

test_80() {
	start_mds || error "Failed to start MDT"
	start_ost || error "Failed to start OST1"
	uuid=$(do_facet ost1 $LCTL get_param -n mgc.*.uuid)
#define OBD_FAIL_MGS_PAUSE_TARGET_CON       0x906
	do_facet ost1 "$LCTL set_param fail_val=10 fail_loc=0x906"
	do_facet mgs "$LCTL set_param fail_val=10 fail_loc=0x906"
	do_facet mgs "$LCTL set_param -n mgs/MGS/evict_client $uuid"
	sleep 30
	start_ost2 || error "Failed to start OST2"

	do_facet ost1 "$LCTL set_param fail_loc=0"
	stop_ost2
	stop_ost
	stop_mds
}
run_test 80 "mgc import reconnect race"

#Save the original values of $OSTCOUNT and $OSTINDEX$i.
save_ostindex() {
	local new_ostcount=$1
	saved_ostcount=$OSTCOUNT
	OSTCOUNT=$new_ostcount

	local i
	local index
	for i in $(seq $OSTCOUNT); do
		index=OSTINDEX$i
		eval saved_ostindex$i=${!index}
		eval OSTINDEX$i=""
	done
}

# Restore the original values of $OSTCOUNT and $OSTINDEX$i.
restore_ostindex() {
	trap 0

	local i
	local index
	for i in $(seq $OSTCOUNT); do
		index=saved_ostindex$i
		eval OSTINDEX$i=${!index}
	done
	OSTCOUNT=$saved_ostcount

	reformat
	if ! combined_mgs_mds ; then
		start_mgs
	fi
}

# The main purpose of this test is to ensure the OST_INDEX_LIST functions as
# expected. This test uses OST_INDEX_LIST to format OSTs with a randomly
# assigned index and ensures we can mount such a formatted file system
test_81() { # LU-4665
	[[ "$MDS1_VERSION" -ge $(version_code 2.6.54) ]] ||
		skip "Need MDS version at least 2.6.54"
	[[ $OSTCOUNT -ge 3 ]] || skip_env "needs >= 3 OSTs"

	stopall

	# Each time RANDOM is referenced, a random integer between 0 and 32767
	# is generated.
	local i
	local saved_ostindex1=$OSTINDEX1
	for i in 65535 $((RANDOM + 65536)); do
		echo -e "\nFormat ost1 with --index=$i, should fail"
		OSTINDEX1=$i
		if add ost1 $(mkfs_opts ost1 $(ostdevname 1)) --reformat \
		   $(ostdevname 1) $(ostvdevname 1); then
			OSTINDEX1=$saved_ostindex1
			error "format ost1 with --index=$i should fail"
		fi
	done
	OSTINDEX1=$saved_ostindex1

	save_ostindex 3

	# Format OSTs with random sparse indices.
	trap "restore_ostindex" EXIT
	echo -e "\nFormat $OSTCOUNT OSTs with sparse indices"
	OST_INDEX_LIST=[0,$((RANDOM * 2 % 65533 + 1)),65534] formatall

	# Setup and check Lustre filesystem.
	start_mgsmds || error "start_mgsmds failed"
	for i in $(seq $OSTCOUNT); do
		start ost$i $(ostdevname $i) $OST_MOUNT_OPTS ||
			error "start ost$i failed"
	done

	mount_client $MOUNT || error "mount client $MOUNT failed"
	check_mount || error "check client $MOUNT failed"

	# Check max_easize.
	local max_easize=$($LCTL get_param -n llite.*.max_easize)
	# 65452 is XATTR_SIZE_MAX less ldiskfs ea overhead
	if large_xattr_enabled; then
		[[ $max_easize -ge 65452 ]] ||
			error "max_easize is $max_easize, should be at least 65452 bytes"
	else
		# LU-11868
		# 4012 is 4096 less ldiskfs ea overhead
		[[ $max_easize -ge 4012 ]] ||
			error "max_easize is $max_easize, should be at least 4012 bytes"
	fi

	restore_ostindex
}
run_test 81 "sparse OST indexing"

# Here we exercise the stripe placement functionality on a file system that
# has formatted the OST with a random index. With the file system the following
# functionality is tested:
#
# 1. Creating a new file with a specific stripe layout.
#
# 2. Modifiy a existing empty file with a specific stripe layout.
#
# 3. Ensure we fail to set the stripe layout of a file that already has one.
#
# 4. If ost-index is defined we need to ensure it is the first entry in the
#    ost index list returned by lfs getstripe.
#
# 5. Lastly ensure this functionality fails with directories.
test_82a() { # LU-4665
	[[ "$MDS1_VERSION" -ge $(version_code 2.6.54) ]] ||
		skip "Need MDS version at least 2.6.54"
	[[ $OSTCOUNT -ge 3 ]] || skip_env "needs >= 3 OSTs"

	stopall

	save_ostindex 3

	# Format OSTs with random sparse indices.
	local i
	local index
	local ost_indices
	local LOV_V1_INSANE_STRIPE_COUNT=65532
	for i in $(seq $OSTCOUNT); do
		index=$(((RANDOM * 2) % LOV_V1_INSANE_STRIPE_COUNT))
		ost_indices+=" $index"
	done
	ost_indices=$(comma_list $ost_indices)

	stack_trap "restore_ostindex" EXIT
	echo -e "\nFormat $OSTCOUNT OSTs with sparse indices $ost_indices"
	OST_INDEX_LIST=[$ost_indices] formatall

	# Setup Lustre filesystem.
	start_mgsmds || error "start_mgsmds failed"
	for i in $(seq $OSTCOUNT); do
		start ost$i $(ostdevname $i) $OST_MOUNT_OPTS ||
			error "start ost$i failed"
	done

	# Collect debug information - start of test
	do_nodes $(comma_list $(mdts_nodes)) \
		   $LCTL get_param osp.*.prealloc_*_id

	mount_client $MOUNT || error "mount client $MOUNT failed"
	wait_osts_up

	$LFS df $MOUNT
	check_lfs_df_ret_val $? || error "$LFS df $MOUNT failed"
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	stack_trap "do_nodes $(comma_list $(mdts_nodes)) \
		   $LCTL get_param osp.*.prealloc_*_id" EXIT

	# 1. If the file does not exist, new file will be created
	#    with specified OSTs.
	local file=$DIR/$tdir/$tfile-1
	local cmd="$LFS setstripe -o $ost_indices $file"
	echo -e "\n$cmd"
	eval $cmd || error "$cmd failed"
	check_stripe_count $file $OSTCOUNT
	check_obdidx $file $ost_indices
	dd if=/dev/urandom of=$file count=1 bs=1M > /dev/null 2>&1 ||
		error "write $file failed"

	# 2. If the file already exists and is an empty file, the file
	#    will be attached with specified layout.
	file=$DIR/$tdir/$tfile-2
	mcreate $file || error "mcreate $file failed"
	cmd="$LFS setstripe -o $ost_indices $file"
	echo -e "\n$cmd"
	eval $cmd || error "$cmd failed"
	dd if=/dev/urandom of=$file count=1 bs=1M > /dev/null 2>&1 ||
		error "write $file failed"
	check_stripe_count $file $OSTCOUNT
	check_obdidx $file $ost_indices

	# 3. If the file already has a valid layout attached, the command
	#    should fail with EBUSY.
	echo -e "\n$cmd"
	eval $cmd && error "stripe is already set on $file, $cmd should fail"

	# 4. If [--stripe-index|-i <start_ost_idx>] is used, the index must
	#    be in the OST indices list.
	local start_ost_idx=${ost_indices##*,}
	file=$DIR/$tdir/$tfile-3
	cmd="$LFS setstripe -o $ost_indices -i $start_ost_idx $file"
	echo -e "\n$cmd"
	eval $cmd || error "$cmd failed"
	check_stripe_count $file $OSTCOUNT
	check_obdidx $file $ost_indices
	check_start_ost_idx $file $start_ost_idx

	file=$DIR/$tdir/$tfile-4
	cmd="$LFS setstripe"
	cmd+=" -o $(exclude_items_from_list $ost_indices $start_ost_idx)"
	cmd+=" -i $start_ost_idx $file"
	echo -e "\n$cmd"
	eval $cmd && error "index $start_ost_idx should be in $ost_indices"

	# 5. Specifying OST indices for directory should succeed.
	local dir=$DIR/$tdir/$tdir
	mkdir $dir || error "mkdir $dir failed"
	cmd="$LFS setstripe -o $ost_indices $dir"
	if [ "$MDS1_VERSION" -gt $(version_code 2.11.53) ] &&
		[ "$CLIENT_VERSION" -gt $(version_code 2.11.53) ]; then
		echo -e "\n$cmd"
		eval $cmd || error "unable to specify OST indices on directory"
	else
		echo "need MDS+client version at least 2.11.53"
	fi

	restore_ostindex
}
run_test 82a "specify OSTs for file (succeed) or directory (succeed)"

cleanup_82b() {
	trap 0

	# Remove OSTs from a pool and destroy the pool.
	destroy_pool $ost_pool || true

	restore_ostindex
}

# Test 82b is run to ensure that if the user supplies a pool with a specific
# stripe layout that it behaves proprerly. It should fail in the case that
# the supplied OST index list points to OSTs not contained in the user
# supplied pool.
test_82b() { # LU-4665
	[[ "$MDS1_VERSION" -ge $(version_code 2.6.54) ]] ||
		skip "Need MDS version at least 2.6.54"
	[[ $OSTCOUNT -ge 4 ]] || skip_env "needs >= 4 OSTs"

	stopall

	save_ostindex 4

	# Format OSTs with random sparse indices.
	local i
	local index
	local ost_indices
	local LOV_V1_INSANE_STRIPE_COUNT=65532
	for i in $(seq $OSTCOUNT); do
		index=$(((RANDOM * 2) % LOV_V1_INSANE_STRIPE_COUNT))
		ost_indices+=" $index"
	done
	ost_indices=$(comma_list $ost_indices)

	trap "restore_ostindex" EXIT
	echo -e "\nFormat $OSTCOUNT OSTs with sparse indices $ost_indices"
	OST_INDEX_LIST=[$ost_indices] formatall

	# Setup Lustre filesystem.
	start_mgsmds || error "start_mgsmds failed"
	for i in $(seq $OSTCOUNT); do
		start ost$i $(ostdevname $i) $OST_MOUNT_OPTS ||
			error "start ost$i failed"
	done

	mount_client $MOUNT || error "mount client $MOUNT failed"

	wait_osts_up
	$LFS df $MOUNT
	check_lfs_df_ret_val $? || error "$LFS df $MOUNT failed"
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	# Create a new pool and add OSTs into it.
	local ost_pool=$FSNAME.$TESTNAME
	create_pool $ost_pool || error "create OST pool $ost_pool failed"

	trap - EXIT
	trap "cleanup_82b" EXIT

	local ost_idx_in_list=${ost_indices##*,}
	local ost_idx_in_pool=$(exclude_items_from_list $ost_indices \
				$ost_idx_in_list)

	local ost_targets="$FSNAME-OST["
	for i in ${ost_idx_in_pool//,/ }; do
		ost_targets=$ost_targets$(printf "%04x," $i)
	done
	ost_targets="${ost_targets%,}]"

	local ost_targets_uuid=$(for i in ${ost_idx_in_pool//,/ }; \
				 do printf "$FSNAME-OST%04x_UUID\n" $i; done |
				 sort -u | tr '\n' ' ')

	local cmd="$LCTL pool_add $ost_pool $ost_targets"
	do_facet mgs $cmd || error "$cmd failed"
	wait_update $HOSTNAME "$LCTL get_param -n lov.$FSNAME-*.pools.$TESTNAME|
			       sort -u | tr '\n' ' ' " "$ost_targets_uuid" ||
					error "wait_update $ost_pool failed"
	wait_update_facet $SINGLEMDS "$LCTL pool_list $ost_pool | wc -l" 4 ||
				error "wait_update pool_list $ost_pool failed"

	# If [--pool|-p <pool_name>] is set with [--ost-list|-o <ost_indices>],
	# then the OSTs must be the members of the pool.
	local file=$DIR/$tdir/$tfile
	cmd="$LFS setstripe -p $ost_pool -o $ost_idx_in_list $file"
	echo -e "\n$cmd"
	eval $cmd && error "OST with index $ost_idx_in_list should be" \
			   "in OST pool $ost_pool"

	# Only select OST $ost_idx_in_list from $ost_pool for file.
	ost_idx_in_list=${ost_idx_in_pool#*,}
	cmd="$LFS setstripe -p $ost_pool -o $ost_idx_in_list $file"
	echo -e "\n$cmd"
	eval $cmd || error "$cmd failed"
	cmd="$LFS getstripe $file"
	echo -e "\n$cmd"
	eval $cmd || error "$cmd failed"
	check_stripe_count $file 2
	check_obdidx $file $ost_idx_in_list
	dd if=/dev/urandom of=$file count=1 bs=1M > /dev/null 2>&1 ||
		error "write $file failed"

	cleanup_82b
}
run_test 82b "specify OSTs for file with --pool and --ost-list options"

test_83() {
	[[ "$OST1_VERSION" -ge $(version_code 2.6.91) ]] ||
		skip "Need OST version at least 2.6.91"
	if [ "$ost1_FSTYPE" != ldiskfs ]; then
		skip "ldiskfs only test"
	fi

	local dev
	local ostmnt
	local fstype
	local mnt_opts

	dev=$(ostdevname 1)
	ostmnt=$(facet_mntpt ost1)

	# Mount the OST as an ldiskfs filesystem.
	log "mount the OST $dev as a $ost1_FSTYPE filesystem"
	add ost1 $(mkfs_opts ost1 $dev) $FSTYPE_OPT \
		--reformat $dev > /dev/null ||
		error "format ost1 error"

	if ! test -b $dev; then
		mnt_opts=$(csa_add "$OST_MOUNT_FS_OPTS" -o loop)
	fi
	echo "mnt_opts $mnt_opts"
	do_facet ost1 mount -t "$ost1_FSTYPE" $dev \
		$ostmnt $mnt_opts
	# Run llverfs on the mounted ldiskfs filesystem.
	# It is needed to get ENOSPACE.
	log "run llverfs in partial mode on the OST $ost1_FSTYPE $ostmnt"
	do_rpc_nodes $(facet_host ost1) run_llverfs $ostmnt -vpl \
		"no" || error "run_llverfs error on $ost1_FSTYPE"

	# Unmount the OST.
	log "unmount the OST $dev"
	stop ost1

	# Delete file IO_scrub. Later osd_scrub_setup will try to
	# create "IO_scrub" but will get ENOSPACE.
	writeconf_all
	echo "start ost1 service on `facet_active_host ost1`"
	start ost1 `ostdevname 1` $OST_MOUNT_OPTS

	local err
	err=$(do_facet ost1 dmesg | grep "VFS: Busy inodes after unmount of")
	echo "string err $err"
	[ -z "$err" ] || error $err
	reformat_and_config
}
run_test 83 "ENOSPACE on OST doesn't cause message VFS: \
Busy inodes after unmount ..."

test_84() {
	local facet=$SINGLEMDS
	local num=$(echo $facet | tr -d "mds")
	local dev=$(mdsdevname $num)
	local time_min=$(recovery_time_min)
	local recovery_duration
	local completed_clients
	local correct_clients
	local wrap_up=5

	echo "start mds service on $(facet_active_host $facet)"
	start_mds \
	"-o recovery_time_hard=$time_min,recovery_time_soft=$time_min" $@ ||
		error "start MDS failed"

	start_ost || error "start OST0000 failed"
	start_ost2 || error "start OST0001 failed"

	echo "recovery_time=$time_min, timeout=$TIMEOUT, wrap_up=$wrap_up"

	mount_client $MOUNT1 || error "mount $MOUNT1 failed"
	mount_client $MOUNT2 || error "mount $MOUNT2 failed"
	# make sure new superblock labels are sync'd before disabling writes
	sync_all_data
	sleep 5

	replay_barrier $SINGLEMDS
	createmany -o $DIR1/$tfile-%d 1000

	# We need to catch the end of recovery window to extend it.
	# Skip 5 requests and add delay to request handling.
	#define OBD_FAIL_TGT_REPLAY_DELAY  0x709 | FAIL_SKIP
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x20000709 fail_val=5"

	facet_failover --fsck $SINGLEMDS || error "failover: $?"
	client_up

	echo "recovery status"
	do_facet $SINGLEMDS \
		"$LCTL get_param -n mdt.$FSNAME-MDT0000.recovery_status"

	recovery_duration=$(do_facet $SINGLEMDS \
		"$LCTL get_param -n mdt.$FSNAME-MDT0000.recovery_status" |
		awk '/recovery_duration/ { print $2 }')
	(( $recovery_duration > $time_min + $wrap_up )) &&
		error "recovery_duration > recovery_time_hard + wrap up"
	completed_clients=$(do_facet $SINGLEMDS \
		"$LCTL get_param -n mdt.$FSNAME-MDT0000.recovery_status" |
		awk '/completed_clients/ { print $2 }')

	correct_clients="$MDSCOUNT/$((MDSCOUNT+1))"
	[ "$completed_clients" = "${correct_clients}" ] ||
		error "$completed_clients != $correct_clients"

	do_facet $SINGLEMDS "lctl set_param fail_loc=0"
	umount_client $MOUNT1
	umount_client $MOUNT2

	stop_ost
	stop_ost2
	stop_mds
}
run_test 84 "check recovery_hard_time"

test_85() {
	[[ "$OST1_VERSION" -ge $(version_code 2.7.55) ]] ||
		skip "Need OST version at least 2.7.55"
##define OBD_FAIL_OSD_OST_EA_FID_SET 0x197
	do_facet ost1 "lctl set_param fail_loc=0x197"
	start_ost
	stop_ost
}
run_test 85 "osd_ost init: fail ea_fid_set"

cleanup_86() {
	trap 0

	# ost1 has already registered to the MGS before the reformat.
	# So after reformatting it with option "-G", it could not be
	# mounted to the MGS. Cleanup the system for subsequent tests.
	reformat_and_config
}

test_86() {
	[ "$ost1_FSTYPE" = zfs ] &&
		skip "LU-6442: no such mkfs params for ZFS OSTs"
	[[ "$MDS1_VERSION" -ge $(version_code 2.7.56) ]] ||
		skip "Need server version newer than 2.7.55"

	local NEWSIZE=1024
	local OLDSIZE=$(do_facet ost1 "$DEBUGFS -c -R stats $(ostdevname 1)" |
		awk '/Flex block group size: / { print $NF; exit; }')

	[ "$OLDSIZE" == "$NEWSIZE" ] && skip "$NEWSIZE groups already"

	local opts=" -O flex_bg -G $NEWSIZE"
	opts=$(OST_FS_MKFS_OPTS+="$opts" mkfs_opts ost1 $(ostdevname 1))
	opts+=" --reformat $(ostdevname 1) $(ostvdevname 1)"
	echo "params: $opts"

	trap cleanup_86 EXIT ERR

	stopall
	add ost1 $opts || error "add ost1 failed with new params"

	local FOUNDSIZE=$(do_facet ost1 "$DEBUGFS -c -R stats $(ostdevname 1)" |
		awk '/Flex block group size: / { print $NF; exit; }')

	[[ $FOUNDSIZE == $NEWSIZE ]] ||
		error "Flex block group size: $FOUNDSIZE, expected: $NEWSIZE"

	cleanup_86
}
run_test 86 "Replacing mkfs.lustre -G option"

test_87() { #LU-6544
	[[ "$MDS1_VERSION" -ge $(version_code 2.9.51) ]] ||
		skip "Need MDS version at least 2.9.51"
	[[ "$mds1_FSTYPE" != ldiskfs ]] &&
		skip "ldiskfs only test"
	[[ $OSTCOUNT -gt 59 ]] &&
		skip "Ignore wide striping situation"
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"

	local mdsdev=$(mdsdevname 1)
	local mdsvdev=$(mdsvdevname 1)
	local file=$DIR/$tfile
	local mntpt=$(facet_mntpt $SINGLEMDS)
	local used_xattr_blk=0
	local inode_size=${1:-1024}
	local left_size=0
	local xtest="trusted.test"
	local value
	local orig
	local i
	local stripe_cnt=$(($OSTCOUNT + 2))

	#Please see ldiskfs_make_lustre() for MDT inode size calculation
	if [ $stripe_cnt -gt 16 ]; then
		inode_size=2048
	fi
	left_size=$(expr $inode_size - \
			156 - \
			32 - \
			32 - 40 \* 3 - 32 \* 3 - $stripe_cnt \* 24 - 16 - 3 -  \
			24 - 16 - 3 - \
			24 - 18 - $(expr length $tfile) - 16 - 4)
	if [ $left_size -le 0 ]; then
		echo "No space($left_size) is expected in inode."
		echo "Try 1-byte xattr instead to verify this."
		left_size=1
	else
		echo "Estimate: at most $left_size-byte space left in inode."
	fi

	unload_modules
	reformat

	if ! combined_mgs_mds ; then
		start_mgs
	fi

	add mds1 $(mkfs_opts mds1 ${mdsdev}) --stripe-count-hint=$stripe_cnt \
		--reformat $mdsdev $mdsvdev || error "add mds1 failed"
	start_mdt 1 > /dev/null || error "start mdt1 failed"
	for i in $(seq $OSTCOUNT); do
		start ost$i $(ostdevname $i) $OST_MOUNT_OPTS > /dev/null ||
			error "start ost$i failed"
	done
	mount_client $MOUNT > /dev/null || error "mount client $MOUNT failed"
	check_mount || error "check client $MOUNT failed"

	#set xattr
	$LFS setstripe -E 1M -S 1M -c 1 -E 64M -c 1 -E -1 -c -1 $file ||
		error "Create file with 3 components failed"
	$TRUNCATE $file $((1024*1024*64+1)) || error "truncate file failed"
	i=$($LFS getstripe -I3 -c $file) || error "get 3rd stripe count failed"
	if [ $i -ne $OSTCOUNT ]; then
		left_size=$(expr $left_size + $(expr $OSTCOUNT - $i) \* 24)
		echo -n "Since only $i out $OSTCOUNT OSTs are used, "
		echo -n "the expected left space is changed to "
		echo "$left_size bytes at most."
	fi
	value=$(generate_string $left_size)
	setfattr -n $xtest -v $value $file
	orig=$(get_xattr_value $xtest $file)
	[[ "$orig" != "$value" ]] && error "$xtest changed"

	#Verify if inode has some expected space left
	umount $MOUNT > /dev/null || error "umount $MOUNT failed"
	stop_mdt 1 > /dev/null || error "stop mdt1 failed"
	mount_ldiskfs $SINGLEMDS || error "mount -t ldiskfs $SINGLEMDS failed"

	do_facet $SINGLEMDS ls -sal $mntpt/ROOT/$tfile
	used_xattr_blk=$(do_facet $SINGLEMDS ls -s $mntpt/ROOT/$tfile |
			awk '{ print $1 }')
	[[ $used_xattr_blk -eq 0 ]] &&
		error "Please check MDS inode size calculation: \
		       more than $left_size-byte space left in inode."
	echo "Verified: at most $left_size-byte space left in inode."

	unmount_ldiskfs $SINGLEMDS

	for i in $(seq $OSTCOUNT); do
		stop ost$i -f || error "stop ost$i failed"
	done
}
run_test 87 "check if MDT inode can hold EAs with N stripes properly"

test_88() {
	[ "$mds1_FSTYPE" == zfs ] &&
		skip "LU-6662: no implementation for ZFS"

	load_modules

	add mds1 $(mkfs_opts mds1 $(mdsdevname 1)) \
		--reformat $(mdsdevname 1) || error "add mds1 failed"

	do_facet mds1 "$TUNEFS $(mdsdevname 1) |
		grep -e \".*opts:.*errors=remount-ro.*\"" ||
		error "default mount options is missing"

	add mds1 $(mkfs_opts mds1 $(mdsdevname 1)) \
		--mountfsoptions="user_xattr,errors=panic" \
		--reformat $(mdsdevname 1) || error "add mds1 failed"

	do_facet mds1 "$TUNEFS $(mdsdevname 1) |
		grep -e \".*opts:.*errors=panic.*\"" ||
		error "user can't override default mount options"
}
run_test 88 "check the default mount options can be overridden"

test_89() { # LU-7131
	[[ "$MDS1_VERSION" -ge $(version_code 2.9.54) ]] ||
		skip "Need MDT version at least 2.9.54"

	local key=failover.node
	local val1=192.0.2.254@tcp0 # Reserved IPs, see RFC 5735
	local val2=192.0.2.255@tcp0
	local mdsdev=$(mdsdevname 1)
	local params

	stopall

	if [[ "$mds1_FSTYPE" == zfs ]]; then
		import_zpool mds1 || return ${PIPESTATUS[0]}
	fi

	# Check that parameters are added correctly
	echo "tunefs --param $key=$val1"
	do_facet mds1 "$TUNEFS --param $key=$val1 $mdsdev >/dev/null" ||
		error "tunefs --param $key=$val1 failed"
	params=$(do_facet mds1 $TUNEFS --dryrun $mdsdev) ||
		error "tunefs --dryrun failed"
	params=${params##*Parameters:}
	params=${params%%exiting*}
	[ $(echo $params | tr ' ' '\n' | grep -c $key=$val1) = "1" ] ||
		error "on-disk parameter not added correctly via tunefs"

	# Check that parameters replace existing instances when added
	echo "tunefs --param $key=$val2"
	do_facet mds1 "$TUNEFS --param $key=$val2 $mdsdev >/dev/null" ||
		error "tunefs --param $key=$val2 failed"
	params=$(do_facet mds1 $TUNEFS --dryrun $mdsdev) ||
		error "tunefs --dryrun failed"
	params=${params##*Parameters:}
	params=${params%%exiting*}
	[ $(echo $params | tr ' ' '\n' | grep -c $key=) = "1" ] ||
		error "on-disk parameter not replaced via tunefs"
	[ $(echo $params | tr ' ' '\n' | grep -c $key=$val2) = "1" ] ||
		error "on-disk parameter not replaced correctly via tunefs"

	# Check that a parameter is erased properly
	echo "tunefs --erase-param $key"
	do_facet mds1 "$TUNEFS --erase-param $key $mdsdev >/dev/null" ||
		error "tunefs --erase-param $key failed"
	params=$(do_facet mds1 $TUNEFS --dryrun $mdsdev) ||
		error "tunefs --dryrun failed"
	params=${params##*Parameters:}
	params=${params%%exiting*}
	[ $(echo $params | tr ' ' '\n' | grep -c $key=) = "0" ] ||
		error "on-disk parameter not erased correctly via tunefs"

	# Check that all the parameters are erased
	do_facet mds1 "$TUNEFS --param $key=$val1 $mdsdev >/dev/null" ||
		error "tunefs --param $key=$val1 failed"
	echo "tunefs --erase-params"
	do_facet mds1 "$TUNEFS --erase-params $mdsdev >/dev/null" ||
		error "tunefs --erase-params failed"
	params=$(do_facet mds1 $TUNEFS --dryrun $mdsdev) ||
		error "tunefs --dryrun failed"
	params=${params##*Parameters:}
	params=${params%%exiting*}
	params=$(echo $params | tr ' ' '\n')
	[ -z "$params" ] ||
		error "all on-disk parameters not erased correctly via tunefs $params"

	# Check the order of options --erase-params and --param
	echo "tunefs --param $key=$val1 --erase-params"
	do_facet mds1 \
		"$TUNEFS --param $key=$val1 --erase-params $mdsdev >/dev/null"||
		error "tunefs --param $key=$val1 --erase-params failed"
	params=$(do_facet mds1 $TUNEFS --dryrun $mdsdev) ||
		error "tunefs --dryrun failed"
	params=${params##*Parameters:}
	params=${params%%exiting*}
	[ $(echo $params | tr ' ' '\n') == "$key=$val1" ] ||
		error "on-disk param not added correctly with --erase-params"

	reformat_and_config
}
run_test 89 "check tunefs --param and --erase-param{s} options"

# $1 test directory
# $2 (optional) value of max_mod_rpcs_in_flight to set
check_max_mod_rpcs_in_flight() {
	local dir="$1"
	local mmr="$2"
	local idx
	local facet
	local tmp
	local i

	idx=$(printf "%04x" $($LFS getdirstripe -i $dir))
	facet="mds$((0x$idx + 1))"

	if [ -z "$mmr" ]; then
		# get value of max_mod_rcps_in_flight
		mmr=$($LCTL get_param -n \
			mdc.$FSNAME-MDT$idx-mdc-*.max_mod_rpcs_in_flight) ||
			error "Unable to get max_mod_rpcs_in_flight"
		echo "max_mod_rcps_in_flight is $mmr"
	else
		# set value of max_mod_rpcs_in_flight
		$LCTL set_param \
		    mdc.$FSNAME-MDT$idx-mdc-*.max_mod_rpcs_in_flight=$mmr ||
			error "Unable to set max_mod_rpcs_in_flight to $mmr"
		echo "max_mod_rpcs_in_flight set to $mmr"
	fi

	# create mmr+1 files
	echo "creating $((mmr + 1)) files ..."
	umask 0022
	for i in $(seq $((mmr + 1))); do
		touch $dir/file-$i
	done

	### part 1 ###

	# consumes mmr-1 modify RPC slots
	#define OBD_FAIL_MDS_REINT_MULTI_NET     0x159
	# drop requests on MDT so that RPC slots are consumed
	# during all the request resend interval
	do_facet $facet "$LCTL set_param fail_loc=0x159"
	echo "launch $((mmr - 1)) chmod in parallel ..."
	for i in $(seq $((mmr - 1))); do
		chmod 0600 $dir/file-$i &
	done
	sleep 1

	# send one additional modify RPC
	do_facet $facet "$LCTL set_param fail_loc=0"
	echo "launch 1 additional chmod in parallel ..."
	chmod 0600 $dir/file-$mmr &
	sleep 1

	# check this additional modify RPC get a modify RPC slot
	# and succeed its operation
	checkstat -vp 0600 $dir/file-$mmr ||
		error "Unable to send $mmr modify RPCs in parallel"
	wait

	### part 2 ###

	# consumes mmr modify RPC slots
	#define OBD_FAIL_MDS_REINT_MULTI_NET     0x159
	# drop requests on MDT so that RPC slots are consumed
	# during all the request resend interval
	do_facet $facet "$LCTL set_param fail_loc=0x159"
	echo "launch $mmr chmod in parallel ..."
	for i in $(seq $mmr); do
		chmod 0666 $dir/file-$i &
	done
	sleep 1

	# send one additional modify RPC
	do_facet $facet "$LCTL set_param fail_loc=0"
	echo "launch 1 additional chmod in parallel ..."
	chmod 0666 $dir/file-$((mmr + 1)) &
	sleep 1

	# check this additional modify RPC blocked getting a modify RPC slot
	checkstat -vp 0644 $dir/file-$((mmr + 1)) ||
		error "Unexpectedly send $(($mmr + 1)) modify RPCs in parallel"
	wait
}

test_90a() {
	setup

	[[ $($LCTL get_param mdc.*.import |
	     grep "connect_flags:.*multi_mod_rpc") ]] ||
		skip "Need MDC with 'multi_mod_rpcs' feature"

	# check default value
	$LFS mkdir -c1 $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	check_max_mod_rpcs_in_flight $DIR/$tdir

	cleanup
}
run_test 90a "check max_mod_rpcs_in_flight is enforced"

test_90b() {
	local idx
	local facet
	local tmp
	local mmrpc

	setup

	[[ $($LCTL get_param mdc.*.import |
	     grep "connect_flags:.*multi_mod_rpc") ]] ||
		skip "Need MDC with 'multi_mod_rpcs' feature"

	### test 1.
	# update max_mod_rpcs_in_flight
	$LFS mkdir -c1 $DIR/${tdir}1 || error "mkdir $DIR/${tdir}1 failed"
	check_max_mod_rpcs_in_flight $DIR/${tdir}1 1

	### test 2.
	# check client is able to send multiple modify RPCs in paralell
	tmp=$($LCTL get_param -n mdc.$FSNAME-MDT*-mdc-*.import |
		grep -c "multi_mod_rpcs")
	if [ "$tmp" -ne $MDSCOUNT ]; then
		cleanup
		skip "Client not able to send multiple modify RPCs in parallel"
	fi

	# update max_mod_rpcs_in_flight
	$LFS mkdir -c1 $DIR/${tdir}2 || error "mkdir $DIR/${tdir}2 failed"
	check_max_mod_rpcs_in_flight $DIR/${tdir}2 5

	### test 3.
	$LFS mkdir -c1 $DIR/${tdir}3 || error "mkdir $DIR/${tdir}3 failed"
	idx=$(printf "%04x" $($LFS getdirstripe -i $DIR/${tdir}3))
	facet="mds$((0x$idx + 1))"

	# save MDT max_mod_rpcs_per_client
	mmrpc=$(do_facet $facet \
		    cat /sys/module/mdt/parameters/max_mod_rpcs_per_client)

	# update max_mod_rpcs_in_flight
	umount_client $MOUNT
	do_facet $facet \
		"echo 16 > /sys/module/mdt/parameters/max_mod_rpcs_per_client"
	mount_client $MOUNT
	$LCTL set_param mdc.$FSNAME-MDT$idx-mdc-*.max_rpcs_in_flight=17
	check_max_mod_rpcs_in_flight $DIR/${tdir}3 16

	# restore MDT max_mod_rpcs_per_client initial value
	do_facet $facet \
		"echo $mmrpc > /sys/module/mdt/parameters/max_mod_rpcs_per_client"

	rm -rf $DIR/${tdir}?
	cleanup
}
run_test 90b "check max_mod_rpcs_in_flight is enforced after update"

save_params_90c() {
	# get max_rpcs_in_flight value
	mrif_90c=$($LCTL get_param -n \
		   mdc.$FSNAME-MDT0000-mdc-*.max_rpcs_in_flight)
	echo "max_rpcs_in_flight is $mrif_90c"

	# get max_mod_rpcs_in_flight value
	mmrif_90c=$($LCTL get_param -n \
		    mdc.$FSNAME-MDT0000-mdc-*.max_mod_rpcs_in_flight)
	echo "max_mod_rpcs_in_flight is $mmrif_90c"

	# get MDT max_mod_rpcs_per_client value
	mmrpc_90c=$(do_facet mds1 \
		    cat /sys/module/mdt/parameters/max_mod_rpcs_per_client)
	echo "max_mod_rpcs_per_client is $mmrpc_90c"
}

restore_params_90c() {
	trap 0

	# restore max_rpcs_in_flight value
	do_facet mgs $LCTL set_param -P \
		mdc.$FSNAME-MDT0000-mdc-*.max_rpcs_in_flight=$mrif_90c

	# restore max_mod_rpcs_in_flight value
	do_facet mgs $LCTL set_param -P \
		mdc.$FSNAME-MDT0000-mdc-*.max_mod_rpcs_in_flight=$mmrif_90c

	# restore MDT max_mod_rpcs_per_client value
	do_facet mds1 "echo $mmrpc_90c > \
		       /sys/module/mdt/parameters/max_mod_rpcs_per_client"
}

test_90c() {
	local tmp

	setup

	[[ $($LCTL get_param mdc.*.import |
	     grep "connect_flags:.*multi_mod_rpc") ]] ||
		skip "Need MDC with 'multi_mod_rpcs' feature"

	# check client is able to send multiple modify RPCs in paralell
	tmp=$($LCTL get_param -n mdc.$FSNAME-MDT*-mdc-*.import |
		grep -c "multi_mod_rpcs")
	if [ "$tmp" -ne $MDSCOUNT ]; then
		cleanup
		skip "Client not able to send multiple modify RPCs in parallel"
	fi

	save_params_90c
	stack_trap restore_params_90c

	# testcase 1
	# attempt to set max_mod_rpcs_in_flight to max_rpcs_in_flight value
	# prerequisite: set max_mod_rpcs_per_client to max_rpcs_in_flight value
	do_facet mds1 "echo $mrif_90c > \
		       /sys/module/mdt/parameters/max_mod_rpcs_per_client"

	# if max_mod_rpcs_in_flight is set to be equal to or larger than
	# max_rpcs_in_flight, then max_rpcs_in_flight will be increased
	if [[ "$CLIENT_VERSION" -ge $(version_code 2.13.53) ]]; then
		$LCTL set_param \
		mdc.$FSNAME-MDT0000-mdc-*.max_mod_rpcs_in_flight=$mrif_90c ||
			error "set max_mod_rpcs_in_flight to $mrif_90c failed"

		local new_mrif=$($LCTL get_param -n \
				 mdc.$FSNAME-MDT0000-mdc-*.max_rpcs_in_flight)
		((new_mrif == mrif_90c + 1)) ||
			error "max_rpcs_in_flight was not increased"
	fi

	umount_client $MOUNT
	do_facet mds1 "echo $mmrpc_90c > \
		       /sys/module/mdt/parameters/max_mod_rpcs_per_client"
	mount_client $MOUNT

	# testcase 2
	# attempt to set max_mod_rpcs_in_flight to max_mod_rpcs_per_client+1
	# prerequisite: set max_rpcs_in_flight to max_mod_rpcs_per_client+2
	$LCTL set_param \
		mdc.$FSNAME-MDT0000-mdc-*.max_rpcs_in_flight=$((mmrpc_90c + 2))

	$LCTL set_param \
	mdc.$FSNAME-MDT0000-mdc-*.max_mod_rpcs_in_flight=$((mmrpc_90c + 1)) &&
	error "set max_mod_rpcs_in_flight to $((mmrpc_90c + 1)) should fail"

	# testcase 3
	# attempt to set max_mod_rpcs_in_flight permanently
	do_facet mgs $LCTL set_param -P \
		mdc.$FSNAME-MDT0000-mdc-*.max_rpcs_in_flight=$mrif_90c

	do_facet mgs $LCTL set_param -P \
		mdc.$FSNAME-MDT0000-mdc-*.max_mod_rpcs_in_flight=$mrif_90c

	remount_client $MOUNT

	wait_update_facet --verbose client "$LCTL get_param -n \
		mdc.$FSNAME-MDT0000-mdc-*.max_rpcs_in_flight" \
		"$((mrif_90c + 1))" ||
		error "expected '$((mrif_90c + 1))' for max_rpcs_in_flight"

	wait_update_facet --verbose client "$LCTL get_param -n \
		mdc.$FSNAME-MDT0000-mdc-*.max_mod_rpcs_in_flight" \
		"$mrif_90c" ||
		error "expected '$mrif_90c' for max_mod_rpcs_in_flight"

	restore_params_90c
	cleanup
}
run_test 90c "check max_mod_rpcs_in_flight update limits"

test_90d() {
	local idx
	local facet
	local mmr
	local i
	local pid

	setup

	[[ $($LCTL get_param mdc.*.import |
	     grep "connect_flags:.*multi_mod_rpc") ]] ||
		skip "Need MDC with 'multi_mod_rpcs' feature"

	$LFS mkdir -c1 $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	idx=$(printf "%04x" $($LFS getdirstripe -i $DIR/$tdir))
	facet="mds$((0x$idx + 1))"

	# check client version supports multislots
	tmp=$($LCTL get_param -N \
		mdc.$FSNAME-MDT$idx-mdc-*.max_mod_rpcs_in_flight)
	if [ -z "$tmp" ]; then
		cleanup
		skip "Client does not support multiple modify RPCs in flight"
	fi

	# get current value of max_mod_rcps_in_flight
	mmr=$($LCTL get_param -n \
		mdc.$FSNAME-MDT$idx-mdc-*.max_mod_rpcs_in_flight)
	echo "max_mod_rcps_in_flight is $mmr"

	# create mmr files
	echo "creating $mmr files ..."
	umask 0022
	for i in $(seq $mmr); do
		touch $DIR/$tdir/file-$i
	done

	# prepare for close RPC
	multiop_bg_pause $DIR/$tdir/file-close O_c
	pid=$!

	# consumes mmr modify RPC slots
	#define OBD_FAIL_MDS_REINT_MULTI_NET     0x159
	# drop requests on MDT so that RPC slots are consumed
	# during all the request resend interval
	do_facet $facet "$LCTL set_param fail_loc=0x159"
	echo "launch $mmr chmod in parallel ..."
	for i in $(seq $mmr); do
		chmod 0600 $DIR/$tdir/file-$i &
	done

	# send one additional close RPC
	do_facet $facet "$LCTL set_param fail_loc=0"
	echo "launch 1 additional close in parallel ..."
	kill -USR1 $pid
	cancel_lru_locks mdc
	sleep 1

	# check this additional close RPC get a modify RPC slot
	# and multiop process completed
	[ -d /proc/$pid ] &&
		error "Unable to send the additional close RPC in parallel"
	wait
	rm -rf $DIR/$tdir
	cleanup
}
run_test 90d "check one close RPC is allowed above max_mod_rpcs_in_flight"

check_uuid_on_ost() {
	local nid=$1
	do_facet ost1 "$LCTL get_param obdfilter.${FSNAME}*.exports.'$nid'.uuid"
}

check_uuid_on_mdt() {
	local nid=$1
	do_facet $SINGLEMDS "$LCTL get_param mdt.${mds1_svc}*.exports.'$nid'.uuid"
}

test_91() {
	local uuid
	local nid
	local found

	[[ "$OST1_VERSION" -ge $(version_code 2.7.63) ]] ||
		skip "Need OST version at least 2.7.63"
	[[ "$MDS1_VERSION" -ge $(version_code 2.7.63) ]] ||
		skip "Need MDT version at least 2.7.63"

	start_mds || error "MDS start failed"
	start_ost || error "unable to start OST"
	mount_client $MOUNT || error "client start failed"
	check_mount || error "check_mount failed"

	if remote_mds; then
		nid=$($LCTL list_nids | head -1 | sed  "s/\./\\\./g")
	else
		nid="0@lo"
	fi
	uuid=$(get_client_uuid $MOUNT)

	echo "list nids on mdt:"
	do_facet $SINGLEMDS "$LCTL list_param mdt.${FSNAME}*.exports.*"
	echo "uuid from $nid:"
	do_facet $SINGLEMDS "$LCTL get_param mdt.${FSNAME}*.exports.'$nid'.uuid"

	found=$(check_uuid_on_mdt $nid | grep $uuid)
	[ -z "$found" ] && error "can't find $uuid $nid on MDT"
	found=$(check_uuid_on_ost $nid | grep $uuid)
	[ -z "$found" ] && error "can't find $uuid $nid on OST"

	# umount the client so it won't reconnect
	manual_umount_client --force || error "failed to umount $?"
	# shouldn't disappear on MDS after forced umount
	found=$(check_uuid_on_mdt $nid | grep $uuid)
	[ -z "$found" ] && error "can't find $uuid $nid"

	echo "evict $nid"
	do_facet $SINGLEMDS \
		"$LCTL set_param -n mdt.${mds1_svc}.evict_client nid:$nid"
	sleep 1 # eviction above is async, give it some time to proceed

	found=$(check_uuid_on_mdt $nid | grep $uuid)
	[ -n "$found" ] && error "found $uuid $nid on MDT"
	found=$(check_uuid_on_ost $nid | grep $uuid)
	[ -n "$found" ] && error "found $uuid $nid on OST"

	# check it didn't reconnect (being umounted)
	sleep $((TIMEOUT+1))
	found=$(check_uuid_on_mdt $nid | grep $uuid)
	[ -n "$found" ] && error "found $uuid $nid on MDT"
	found=$(check_uuid_on_ost $nid | grep $uuid)
	[ -n "$found" ] && error "found $uuid $nid on OST"

	cleanup
}
run_test 91 "evict-by-nid support"

generate_ldev_conf() {
	# generate an ldev.conf file
	local ldevconfpath=$1
	local fstype=
	local fsldevformat=""
	touch $ldevconfpath

	fstype=$(facet_fstype mgs)
	if [ "$fstype" == zfs ]; then
		fsldevformat="$fstype:"
	else
		fsldevformat=""
	fi

	printf "%s\t-\t%s-MGS0000\t%s%s\n" \
		$mgs_HOST \
		$FSNAME \
		$fsldevformat \
		$(mgsdevname) > $ldevconfpath

	local mdsfo_host=$mdsfailover_HOST;
	if [ -z "$mdsfo_host" ]; then
		mdsfo_host="-"
	fi

	for num in $(seq $MDSCOUNT); do
		fstype=$(facet_fstype mds$num)
		if [ "$fstype" == zfs ]; then
			fsldevformat="$fstype:"
		else
			fsldevformat=""
		fi

		printf "%s\t%s\t%s-MDT%04d\t%s%s\n" \
			$mds_HOST \
			$mdsfo_host \
			$FSNAME \
			$num \
			$fsldevformat \
			$(mdsdevname $num) >> $ldevconfpath
	done

	local ostfo_host=$ostfailover_HOST;
	if [ -z "$ostfo_host" ]; then
		ostfo_host="-"
	fi

	for num in $(seq $OSTCOUNT); do
		fstype=$(facet_fstype ost$num)
		if [ "$fstype" == zfs ]; then
			fsldevformat="$fstype:"
		else
			fsldevformat=""
		fi

		printf "%s\t%s\t%s-OST%04d\t%s%s\n" \
			$ost_HOST \
			$ostfo_host \
			$FSNAME \
			$num \
			$fsldevformat \
			$(ostdevname $num) >> $ldevconfpath
	done

	echo "----- $ldevconfpath -----"
	cat $ldevconfpath
	echo "--- END $ldevconfpath ---"

}

generate_nids() {
	# generate a nids file (mapping between hostname to nid)
	# looks like we only have the MGS nid available to us
	# so just echo that to a file
	local nidspath=$1
	echo -e "${mgs_HOST}\t${MGSNID}" > $nidspath

	echo "----- $nidspath -----"
	cat $nidspath
	echo "--- END $nidspath ---"
}

compare_ldev_output() {
	ldev_output=$1
	expected_output=$2

	sort $expected_output -o $expected_output
	sort $ldev_output -o $ldev_output

	echo "-- START OF LDEV OUTPUT --"
	cat $ldev_output
	echo "--- END OF LDEV OUTPUT ---"

	echo "-- START OF EXPECTED OUTPUT --"
	cat $expected_output
	echo "--- END OF EXPECTED OUTPUT ---"

	diff $expected_output $ldev_output
	return $?
}

test_92() {
	if [ -z "$LDEV" ]; then
		error "ldev is missing!"
	fi

	local LDEVCONFPATH=$TMP/ldev.conf
	local NIDSPATH=$TMP/nids

	echo "Host is $(hostname)"

	generate_ldev_conf $LDEVCONFPATH
	generate_nids $NIDSPATH

	# echo the mgs nid and compare it to environment variable MGSNID
	# also, ldev.conf and nids is a server side thing, use the OSS
	# hostname
	local output
	output=$($LDEV -c $LDEVCONFPATH -H $ost_HOST -n $NIDSPATH echo %m)

	echo "-- START OF LDEV OUTPUT --"
	echo -e "$output"
	echo "--- END OF LDEV OUTPUT ---"

	# ldev failed, error
	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev failed to execute!"
	fi

	# need to process multiple lines because of combined MGS and MDS
	echo -e $output | awk '{ print $2 }' | while read -r line ; do
		if [ "$line" != "$MGSNID" ]; then
			rm $LDEVCONFPATH $NIDSPATH
			error "ldev failed mgs nid '$line', expected '$MGSNID'"
		fi
	done

	rm $LDEVCONFPATH $NIDSPATH
}
run_test 92 "ldev returns MGS NID correctly in command substitution"

test_93() {
	[ $MDSCOUNT -lt 3 ] && skip "needs >= 3 MDTs"

	reformat
	#start mgs or mgs/mdt0
	if ! combined_mgs_mds ; then
		start_mgs
		start_mdt 1
	else
		start_mdt 1
	fi

	start_ost || error "OST0 start fail"

	#define OBD_FAIL_MGS_WRITE_TARGET_DELAY	 0x90e
	do_facet mgs "$LCTL set_param fail_val=10 fail_loc=0x8000090e"
	for num in $(seq 2 $MDSCOUNT); do
		start_mdt $num &
	done

	mount_client $MOUNT || error "mount client fails"
	wait_osc_import_state mds ost FULL
	wait_osc_import_ready client ost
	check_mount || error "check_mount failed"

	cleanup || error "cleanup failed with $?"
}
run_test 93 "register mulitple MDT at the same time"

test_94() {
	if [ -z "$LDEV" ]; then
		error "ldev is missing!"
	fi

	local LDEVCONFPATH=$TMP/ldev.conf
	local NIDSPATH=$TMP/nids

	generate_ldev_conf $LDEVCONFPATH
	generate_nids $NIDSPATH

	local LDEV_OUTPUT=$TMP/ldev-output.txt
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -F $FSNAME > $LDEV_OUTPUT

	# ldev failed, error
	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH $LDEV_OUTPUT
		error "ldev failed to execute!"
	fi

	# expected output
	local EXPECTED_OUTPUT=$TMP/ldev-expected.txt

	printf "%s-MGS0000\n" $FSNAME > $EXPECTED_OUTPUT

	for num in $(seq $MDSCOUNT); do
		printf "%s-MDT%04d\n" $FSNAME $num >> $EXPECTED_OUTPUT
	done

	for num in $(seq $OSTCOUNT); do
		printf "%s-OST%04d\n" $FSNAME $num >> $EXPECTED_OUTPUT
	done

	compare_ldev_output $LDEV_OUTPUT $EXPECTED_OUTPUT

	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH $EXPECTED_OUTPUT $LDEV_OUTPUT
		error "ldev failed to produce the correct hostlist!"
	fi

	rm $LDEVCONFPATH $NIDSPATH $EXPECTED_OUTPUT $LDEV_OUTPUT
}
run_test 94 "ldev outputs correct labels for file system name query"

test_95() {
	if [ -z "$LDEV" ]; then
		error "ldev is missing!"
	fi

	local LDEVCONFPATH=$TMP/ldev.conf
	local NIDSPATH=$TMP/nids

	generate_ldev_conf $LDEVCONFPATH
	generate_nids $NIDSPATH

	# SUCCESS CASES
	# file sys filter
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -F $FSNAME &>/dev/null
	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev label filtering w/ -F failed!"
	fi

	# local filter
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -l  &>/dev/null
	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev label filtering w/ -l failed!"
	fi

	# foreign filter
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -f &>/dev/null
	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev label filtering w/ -f failed!"
	fi

	# all filter
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -a &>/dev/null
	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev label filtering w/ -a failed!"
	fi

	# FAILURE CASES
	# all & file sys
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -a -F $FSNAME &>/dev/null
	if [ $? -eq 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev label filtering w/ -a and -F incorrectly succeeded"
	fi

	# all & foreign
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -a -f &>/dev/null
	if [ $? -eq 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev label filtering w/ -a and -f incorrectly succeeded"
	fi

	# all & local
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -a -l &>/dev/null
	if [ $? -eq 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev label filtering w/ -a and -l incorrectly succeeded"
	fi

	# foreign & local
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -f -l &>/dev/null
	if [ $? -eq 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev label filtering w/ -f and -l incorrectly succeeded"
	fi

	# file sys & local
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -F $FSNAME -l &>/dev/null
	if [ $? -eq 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev label filtering w/ -F and -l incorrectly succeeded"
	fi

	# file sys & foreign
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -F $FSNAME -f &>/dev/null
	if [ $? -eq 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH
		error "ldev label filtering w/ -F and -f incorrectly succeeded"
	fi

	rm $LDEVCONFPATH $NIDSPATH
}
run_test 95 "ldev should only allow one label filter"

test_96() {
	if [ -z "$LDEV" ]; then
		error "ldev is missing!"
	fi

	local LDEVCONFPATH=$TMP/ldev.conf
	local NIDSPATH=$TMP/nids

	generate_ldev_conf $LDEVCONFPATH
	generate_nids $NIDSPATH

	local LDEV_OUTPUT=$TMP/ldev-output.txt
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -H $mgs_HOST \
		echo %H-%b | \
		awk '{print $2}' > $LDEV_OUTPUT

	# ldev failed, error
	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH $LDEV_OUTPUT
		error "ldev failed to execute!"
	fi

	# expected output
	local EXPECTED_OUTPUT=$TMP/ldev-expected-output.txt

	echo "$mgs_HOST-$(facet_fstype mgs)" > $EXPECTED_OUTPUT

	if [ "$mgs_HOST" == "$mds_HOST" ]; then
		for num in $(seq $MDSCOUNT); do
			echo "$mds_HOST-$(facet_fstype mds$num)" \
			>> $EXPECTED_OUTPUT
		done
	fi

	if [ "$mgs_HOST" == "$ost_HOST" ]; then
		for num in $(seq $OSTCOUNT); do
			echo "$ost_HOST-$(facet_fstype ost$num)" \
			>> $EXPECTED_OUTPUT
		done
	fi

	compare_ldev_output $LDEV_OUTPUT $EXPECTED_OUTPUT

	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH $EXPECTED_OUTPUT $LDEV_OUTPUT
		error "ldev failed to produce the correct output!"
	fi

	rm $LDEVCONFPATH $NIDSPATH $EXPECTED_OUTPUT $LDEV_OUTPUT
}
run_test 96 "ldev returns hostname and backend fs correctly in command sub"

test_97() {
	if [ -z "$LDEV" ]; then
		error "ldev is missing!"
	fi

	local LDEVCONFPATH=$TMP/ldev.conf
	local NIDSPATH=$TMP/nids

	generate_ldev_conf $LDEVCONFPATH
	generate_nids $NIDSPATH

	local LDEV_OUTPUT=$TMP/ldev-output.txt
	local EXPECTED_OUTPUT=$TMP/ldev-expected-output.txt

	echo -e "\nMDT role"
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -F $FSNAME -R mdt > $LDEV_OUTPUT

	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH $LDEV_OUTPUT
		error "ldev failed to execute for mdt role!"
	fi

	for num in $(seq $MDSCOUNT); do
		printf "%s-MDT%04d\n" $FSNAME $num >> $EXPECTED_OUTPUT
	done

	compare_ldev_output $LDEV_OUTPUT $EXPECTED_OUTPUT

	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH $EXPECTED_OUTPUT $LDEV_OUTPUT
		error "ldev failed to produce the correct output for mdt role!"
	fi

	echo -e "\nOST role"
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -F $FSNAME -R ost > $LDEV_OUTPUT

	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH $LDEV_OUTPUT $EXPECTED_OUTPUT
		error "ldev failed to execute for ost role!"
	fi

	rm $EXPECTED_OUTPUT
	for num in $(seq $OSTCOUNT); do
		printf "%s-OST%04d\n" $FSNAME $num >> $EXPECTED_OUTPUT
	done

	compare_ldev_output $LDEV_OUTPUT $EXPECTED_OUTPUT

	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH $EXPECTED_OUTPUT $LDEV_OUTPUT
		error "ldev failed to produce the correct output for ost role!"
	fi

	echo -e "\nMGS role"
	$LDEV -c $LDEVCONFPATH -n $NIDSPATH -F $FSNAME -R mgs > $LDEV_OUTPUT

	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH $LDEV_OUTPUT $EXPECTED_OUTPUT
		error "ldev failed to execute for mgs role!"
	fi

	printf "%s-MGS0000\n" $FSNAME > $EXPECTED_OUTPUT

	compare_ldev_output $LDEV_OUTPUT $EXPECTED_OUTPUT

	if [ $? -ne 0 ]; then
		rm $LDEVCONFPATH $NIDSPATH $EXPECTED_OUTPUT $LDEV_OUTPUT
		error "ldev failed to produce the correct output for mgs role!"
	fi

	rm $LDEVCONFPATH $NIDSPATH $EXPECTED_OUTPUT $LDEV_OUTPUT
}
run_test 97 "ldev returns correct ouput when querying based on role"

test_98()
{
	local mountopt
	local temp=$MDS_MOUNT_OPTS

	setup
	check_mount || error "mount failed"
	mountopt="user_xattr"
	for ((x = 1; x <= 400; x++)); do
		mountopt="$mountopt,user_xattr"
	done
	mount_client $MOUNT remount,$mountopt 2>&1 | grep "too long" ||
		error "Buffer overflow check failed"
	cleanup || error "cleanup failed"
}
run_test 98 "Buffer-overflow check while parsing mount_opts"

test_99()
{
	[[ "$ost1_FSTYPE" != ldiskfs ]] &&
		skip "ldiskfs only test"
	[[ "$OST1_VERSION" -ge $(version_code 2.8.57) ]] ||
		skip "Need OST version at least 2.8.57"

	local ost_opts="$(mkfs_opts ost1 $(ostdevname 1)) \
		--reformat $(ostdevname 1) $(ostvdevname 1)"
	do_facet ost1 $DEBUGFS -c -R stats `ostdevname 1` | grep "meta_bg" &&
		skip "meta_bg already set"

	local opts=ost_opts
	if [[ ${!opts} != *mkfsoptions* ]]; then
		eval opts=\"${!opts} \
		--mkfsoptions='\\\"-O ^resize_inode,meta_bg\\\"'\"
	else
		local val=${!opts//--mkfsoptions=\\\"/ \
		--mkfsoptions=\\\"-O ^resize_inode,meta_bg }
		eval opts='${val}'
	fi

	echo "params: $opts"

	load_modules
	add ost1 $opts || error "add ost1 failed with new params"

	do_facet ost1 $DEBUGFS -c -R stats `ostdevname 1` | grep "meta_bg" ||
		error "meta_bg is not set"
}
run_test 99 "Adding meta_bg option"

test_100() {
	reformat

	start_mgsmds || error "MDS start failed"
	start_ost || error "unable to start OST"
	mount_client $MOUNT || error "client start failed"
	check_mount || error "check_mount failed"

	# Desired output
	# MGS:
	#     0@lo
	# $FSNAME-MDT0000:
	#     0@lo
	# $FSNAME-OST0000:
	#     0@lo
	do_facet mgs 'lshowmount -v' | awk 'BEGIN {NR == 0; rc=1} /MGS:/ {rc=0}
		END {exit rc}' || error "lshowmount have no output MGS"

	do_facet mds1 'lshowmount -v' | awk 'BEGIN {NR == 2; rc=1} /-MDT0000:/
		{rc=0} END {exit rc}' || error "lshowmount have no output MDT0"

	do_facet ost1 'lshowmount -v' | awk 'BEGIN {NR == 4; rc=1} /-OST0000:/
		{rc=0} END {exit rc}' || error "lshowmount have no output OST0"

	cleanup || error "cleanup failed with $?"
}
run_test 100 "check lshowmount lists MGS, MDT, OST and 0@lo"

test_101a() {
	local createmany_pid
	local dev=$FSNAME-OST0000-osc-MDT0000
	setup

	mkdir $DIR1/$tdir
	createmany -o $DIR1/$tdir/$tfile-%d 50000 &
	createmany_pid=$!
	# MDT->OST reconnection causes MDT<->OST last_id synchornisation
	# via osp_precreate_cleanup_orphans.
	for ((i = 0; i < 100; i++)); do
		for ((k = 0; k < 10; k++)); do
			do_facet $SINGLEMDS "$LCTL --device $dev deactivate;" \
					    "$LCTL --device $dev activate"
		done

		ls -asl $MOUNT | grep '???' &&
			{ kill -9 $createmany_pid &>/dev/null;
			  error "File has no object on OST"; }

		kill -s 0 $createmany_pid || break
	done
	wait $createmany_pid

	unlinkmany $DIR1/$tdir/$tfile-%d 50000
	cleanup
}
run_test 101a "Race MDT->OST reconnection with create"

test_101b () {
	local dev=$FSNAME-OST0000-osc-MDT0000
	local dir=$DIR1/$tdir
	setup

	mkdir $dir
	$LFS setstripe -c 1 -i 0 $dir
	do_facet $SINGLEMDS "$LCTL --device $dev deactivate;"
#define OBD_FAIL_OSP_CON_EVENT_DELAY 0x2107
	do_facet mds1 "$LCTL set_param fail_loc=0x80002107 fail_val=20"
	do_facet $SINGLEMDS "$LCTL --device $dev activate;"
	stop_ost
	sleep 25
	start_ost

	wait_osc_import_state client ost1 FULL
	touch $dir/$tfile || error "Can't create file"

	cleanup
}
run_test 101b "Race events DISCONNECT and ACTIVE in osp"

test_102() {
	[[ "$MDS1_VERSION" -gt $(version_code 2.9.53) ]] ||
		skip "Need server version greater than 2.9.53"
	[[ “$(mdsdevname 1)” != “$(mgsdevname)” ]] &&
		[[ “$(facet_host mds1)” = “$(facet_host mgs)” ]] &&
		skip "MGS must be on different node or combined"

	cleanup || error "cleanup failed with $?"

	local mds1dev=$(mdsdevname 1)
	local mds1mnt=$(facet_mntpt mds1)
	local mds1opts=$MDS_MOUNT_OPTS

	if [ "$mds1_FSTYPE" == ldiskfs ] &&
	   ! do_facet mds1 test -b $mds1dev; then
		mds1opts=$(csa_add "$mds1opts" -o loop)
	fi
	if [[ "$mds1_FSTYPE" == zfs ]]; then
		import_zpool mds1 || return ${PIPESTATUS[0]}
	fi

	# unload all and only load libcfs to allow fail_loc setting
	do_facet mds1 $LUSTRE_RMMOD || error "unable to unload modules"
	do_facet mds1 modprobe libcfs || error "libcfs not loaded"
	do_facet mds1 lsmod \| grep libcfs || error "libcfs not loaded"

	#define OBD_FAIL_OBDCLASS_MODULE_LOAD    0x60a
	do_facet mds1 "$LCTL set_param fail_loc=0x8000060a"

	do_facet mds1 $MOUNT_CMD $mds1dev $mds1mnt $mds1opts &&
		error "mdt start must fail"
	do_facet mds1 lsmod \| grep  obdclass && error "obdclass must not load"

	do_facet mds1 "$LCTL set_param fail_loc=0x0"

	do_facet mds1 $MOUNT_CMD $mds1dev $mds1mnt $mds1opts ||
		error "mdt start must not fail"

	cleanup || error "cleanup failed with $?"
}
run_test 102 "obdclass module cleanup upon error"

test_renamefs() {
	local newname=$1

	echo "rename $FSNAME to $newname"

	if ! combined_mgs_mds ; then
		local dev=$(mgsdevname)

		do_facet mgs \
			"$TUNEFS --fsname=$newname --rename=$FSNAME -v $dev" ||
				error "(7) Fail to rename MGS"
		if [ "$(facet_fstype mgs)" = "zfs" ]; then
			reimport_zpool mgs $newname-mgs
		fi
	fi

	for num in $(seq $MDSCOUNT); do
		local dev=$(mdsdevname $num)

		do_facet mds${num} \
			"$TUNEFS --fsname=$newname --rename=$FSNAME -v $dev" ||
				error "(8) Fail to rename MDT $num"
		if [ "$(facet_fstype mds${num})" = "zfs" ]; then
			reimport_zpool mds${num} $newname-mdt${num}
		fi
	done

	for num in $(seq $OSTCOUNT); do
		local dev=$(ostdevname $num)

		do_facet ost${num} \
			"$TUNEFS --fsname=$newname --rename=$FSNAME -v $dev" ||
				error "(9) Fail to rename OST $num"
		if [ "$(facet_fstype ost${num})" = "zfs" ]; then
			reimport_zpool ost${num} $newname-ost${num}
		fi
	done
}

test_103_set_pool() {
	local pname=$1
	local ost_x=$2

	do_facet mgs $LCTL pool_add $FSNAME.$pname ${FSNAME}-$ost_x ||
		error "Fail to add $ost_x to $FSNAME.$pname"
	wait_update $HOSTNAME \
		"lctl get_param -n lov.$FSNAME-clilov-*.pools.$pname |
		 grep $ost_x" "$FSNAME-${ost_x}_UUID" ||
		error "$ost_x is NOT in pool $FSNAME.$pname"
}

test_103_check_pool() {
	local save_fsname=$1
	local errno=$2

	stat $DIR/$tdir/test-framework.sh ||
		error "($errno) Fail to stat"
	do_facet mgs $LCTL pool_list $FSNAME.pool1 ||
		error "($errno) Fail to list $FSNAME.pool1"
	do_facet mgs $LCTL pool_list $FSNAME.$save_fsname ||
		error "($errno) Fail to list $FSNAME.$save_fsname"
	do_facet mgs $LCTL pool_list $FSNAME.$save_fsname |
		grep ${FSNAME}-OST0000 ||
		error "($errno) List $FSNAME.$save_fsname is invalid"

	local pname=$($LFS getstripe --pool $DIR/$tdir/d0)
	[ "$pname" = "$save_fsname" ] ||
		error "($errno) Unexpected pool name $pname"
}

test_103() {
	check_mount_and_prep
	rm -rf $DIR/$tdir
	mkdir $DIR/$tdir || error "(1) Fail to mkdir $DIR/$tdir"
	cp $LUSTRE/tests/test-framework.sh $DIR/$tdir ||
		error "(2) Fail to copy test-framework.sh"

	do_facet mgs $LCTL pool_new $FSNAME.pool1 ||
		error "(3) Fail to create $FSNAME.pool1"
	# name the pool name as the fsname
	do_facet mgs $LCTL pool_new $FSNAME.$FSNAME ||
		error "(4) Fail to create $FSNAME.$FSNAME"

	test_103_set_pool $FSNAME OST0000

	$LFS setstripe -p $FSNAME $DIR/$tdir/d0 ||
		error "(6) Fail to setstripe on $DIR/$tdir/d0"

	KEEP_ZPOOL=true
	stopall

	test_renamefs mylustre

	local save_fsname=$FSNAME
	FSNAME="mylustre"
	setupall

	test_103_check_pool $save_fsname 7

	if [ $OSTCOUNT -ge 2 ]; then
		test_103_set_pool $save_fsname OST0001
	fi

	$LFS setstripe -p $save_fsname $DIR/$tdir/f0 ||
		error "(16) Fail to setstripe on $DIR/$tdir/f0"

	stopall

	test_renamefs tfs

	FSNAME="tfs"
	setupall

	test_103_check_pool $save_fsname 17

	stopall

	test_renamefs $save_fsname

	FSNAME=$save_fsname
	setupall
	KEEP_ZPOOL=false
}
run_test 103 "rename filesystem name"

test_104a() { # LU-6952
	local mds_mountopts=$MDS_MOUNT_OPTS
	local ost_mountopts=$OST_MOUNT_OPTS
	local mds_mountfsopts=$MDS_MOUNT_FS_OPTS
	local lctl_ver=$(do_facet $SINGLEMDS $LCTL --version |
			awk '{ print $2 }')

	[[ $(version_code $lctl_ver) -lt $(version_code 2.9.55) ]] &&
		skip "this test needs utils above 2.9.55"

	# specify "acl" in mount options used by mkfs.lustre
	if [ -z "$MDS_MOUNT_FS_OPTS" ]; then
		MDS_MOUNT_FS_OPTS="acl,user_xattr"
	else

		MDS_MOUNT_FS_OPTS="${MDS_MOUNT_FS_OPTS},acl,user_xattr"
	fi

	echo "mountfsopt: $MDS_MOUNT_FS_OPTS"

	#reformat/remount the MDT to apply the MDT_MOUNT_FS_OPT options
	formatall
	if ! combined_mgs_mds ; then
		start_mgs
	fi

	if [ -z "$MDS_MOUNT_OPTS" ]; then
		MDS_MOUNT_OPTS="-o noacl"
	else
		MDS_MOUNT_OPTS="${MDS_MOUNT_OPTS},noacl"
	fi

	for num in $(seq $MDSCOUNT); do
		start mds$num $(mdsdevname $num) $MDS_MOUNT_OPTS ||
			error "Failed to start MDS"
	done

	for num in $(seq $OSTCOUNT); do
		start ost$num $(ostdevname $num) $OST_MOUNT_OPTS ||
			error "Failed to start OST"
	done

	mount_client $MOUNT
	setfacl -m "d:$RUNAS_ID:rwx" $MOUNT &&
		error "ACL is applied when FS is mounted with noacl."

	MDS_MOUNT_OPTS=$mds_mountopts
	OST_MOUNT_OPTS=$ost_mountopts
	MDS_MOUNT_FS_OPTS=$mds_mountfsopts
}
run_test 104a "Make sure user defined options are reflected in mount"

test_104b() { # LU-12859
	mount_client $MOUNT3 flock,localflock
	stack_trap "umount_client $MOUNT3" EXIT
	mount | grep "$MOUNT3 .*,flock" && error "flock is still set"
	mount | grep "$MOUNT3 .*,localflock" || error "localflock is not set"
	umount_client $MOUNT3
	mount_client $MOUNT3 localflock,flock
	mount | grep "$MOUNT3 .*,localflock" && error "localflock is still set"
	mount | grep "$MOUNT3 .*,flock" || error "flock is not set"
	umount_client $MOUNT3
	mount_client $MOUNT3 localflock,flock,noflock
	flock_is_enabled $MOUNT3 && error "some flock is still enabled" || true
}
run_test 104b "Mount uses last flock argument"

error_and_umount() {
	umount $TMP/$tdir
	rmdir $TMP/$tdir
	error $*
}

test_105() {
	cleanup -f
	reformat
	setup_noconfig
	mkdir -p $TMP/$tdir
	mount --bind $DIR $TMP/$tdir || error "mount bind mnt pt failed"
	rm -f $TMP/$tdir/$tfile
	rm -f $TMP/$tdir/${tfile}1

	# Files should not be created in ro bind mount point
	# remounting from rw to ro
	mount -o remount,ro $TMP/$tdir ||
		error_and_umount "readonly remount of bind mnt pt failed"
	touch $TMP/$tdir/$tfile &&
		error_and_umount "touch succeeds on ro bind mnt pt"
	[ -e $TMP/$tdir/$tfile ] &&
		error_and_umount "file created on ro bind mnt pt"

	# Files should be created in rw bind mount point
	# remounting from ro to rw
	mount -o remount,rw $TMP/$tdir ||
		error_and_umount "read-write remount of bind mnt pt failed"
	touch $TMP/$tdir/${tfile}1 ||
		error_and_umount "touch fails on rw bind mnt pt"
	[ -e $TMP/$tdir/${tfile}1 ] ||
		error_and_umount "file not created on rw bind mnt pt"
	umount $TMP/$tdir || error "umount of bind mnt pt failed"
	rmdir $TMP/$tdir
	cleanup || error "cleanup failed with $?"
}
run_test 105 "check file creation for ro and rw bind mnt pt"

test_106() {
	local repeat=5

	reformat
	setup_noconfig
	mkdir -p $DIR/$tdir || error "create $tdir failed"
	lfs setstripe -c 1 -i 0 $DIR/$tdir
#define OBD_FAIL_CAT_RECORDS                        0x1312
	do_facet mds1 $LCTL set_param fail_loc=0x1312 fail_val=$repeat

	for ((i = 1; i <= $repeat; i++)); do

		#one full plain llog
		createmany -o $DIR/$tdir/f- 64768

		createmany -u $DIR/$tdir/f- 64768
	done
	wait_delete_completed $((TIMEOUT * 7))
#ASSERTION osp_sync_thread() ( thread->t_flags != SVC_RUNNING ) failed
#shows that osp code is buggy
	do_facet mds1 $LCTL set_param fail_loc=0 fail_val=0

	cleanup
}
run_test 106 "check osp llog processing when catalog is wrapped"

test_107() {
	[[ "$MDS1_VERSION" -ge $(version_code 2.10.50) ]] ||
		skip "Need MDS version > 2.10.50"
	local cmd

	start_mgsmds || error "start_mgsmds failed"
	start_ost || error "unable to start OST"

	# add unknown configuration parameter.
	if [[ $PERM_CMD == *"set_param -P"* ]]; then
		cmd="$PERM_CMD ost.$FSNAME-OST0000*.unknown_param"
	else
		cmd="$PERM_CMD $FSNAME-OST0000*.ost.unknown_param"
	fi
	do_facet mgs "$cmd=50"
	cleanup_nocli || error "cleanup_nocli failed with $?"
	load_modules

	# unknown param should be ignored while mounting.
	start_ost || error "unable to start OST after unknown param set"

	cleanup || error "cleanup failed with $?"
}
run_test 107 "Unknown config param should not fail target mounting"

t_108_prep() {
	local facet

	$rcmd rm -rf $tmp > /dev/null 2>&1
	$rcmd mkdir -p $tmp/{mnt,images} || error "failed to mkdir remotely"

	for facet in $facets; do
		[ "$mds1_FSTYPE" = zfs ] &&
			$rcmd $ZPOOL -f export lustre-$facet > /dev/null 2>&1
		$rcmd mkdir $tmp/mnt/$facet ||
			error "failed to mkdir $tmp/mnt/$facet"
		$rcmd dd if=/dev/zero of=$tmp/images/$facet \
			seek=199 bs=1M count=1 ||
			error "failed to create $tmp/images/$facet"
	done
}

t_108_mkfs() {
	local role=$1
	local idx=$2
	local bkfs=$3
	local mgs=$4
	local facet=${role}$((idx + 1))
	local pool=""
	[ $# -eq 5 ] && pool=$5

	do_facet $SINGLEMDS $MKFS --fsname=lustre --$mgs \
		--$role --index=$idx --replace --backfstype=$bkfs \
		--device-size=200000 --reformat $pool $tmp/images/$facet ||
		error "failed to mkfs for $facet"
}

t_108_check() {
	echo "mounting client..."
	mount -t lustre ${nid}:/lustre $MOUNT ||
		error "failed to mount lustre"

	echo "check list"
	ls -l $MOUNT/local_dir || error "failed to list"

	echo "check truncate && write"
	echo "dummmmmmmmmmmmm" > $MOUNT/remote_dir/fsx.c ||
		error "failed to tuncate & write"

	echo "check create"
	touch $MOUNT/foooo ||
		error "failed to create"

	echo "check read && write && append"
	sha1sum $MOUNT/conf-sanity.sh |
		awk '{ print $1 }' > $MOUNT/checksum.new ||
		error "failed to read(1)"
	sha1sum $MOUNT/remote_dir/unlinkmany.c |
		awk '{ print $1 }' >> $MOUNT/checksum.new ||
		error "failed to read(2)"
	sha1sum $MOUNT/striped_dir/lockahead_test.o |
		awk '{ print $1 }' >> $MOUNT/checksum.new ||
		error "failed to read(3)"

	echo "verify data"
	diff $MOUNT/checksum.new $MOUNT/checksum.src ||
		error "failed to verify data"

	echo "done."
}

t_108_cleanup() {
	trap 0
	local facet

	echo "cleanup..."
	umount -f $MOUNT || error "failed to umount client"
	for facet in $facets; do
		$rcmd umount -f $tmp/mnt/$facet ||
			error "failed to umount $facet"
		if [ "$mds1_FSTYPE" = zfs ]; then
			$rcmd $ZPOOL export -f lustre-$facet ||
				error "failed to export lustre-$facet"
		fi
	done

	$rcmd rm -rf $tmp || error "failed to rm the dir $tmp"
}

test_108a() {
	[ "$CLIENTONLY" ] && skip "Client-only testing"
	[ "$mds1_FSTYPE" != zfs ] && skip "zfs only test"
	[ "$MDS1_VERSION" -lt $(version_code 2.10.58) ] &&
		skip "Need server version at least 2.10.58"

	stopall
	load_modules

	local tmp=$TMP/$tdir
	local rcmd="do_facet $SINGLEMDS"
	local facets="mdt1 mdt2 ost1 ost2"
	local nid=$($rcmd $LCTL list_nids | head -1)
	local facet

	trap t_108_cleanup EXIT ERR
	t_108_prep

	t_108_mkfs mdt 0 zfs mgs lustre-mdt1/mdt1
	t_108_mkfs mdt 1 zfs mgsnode=$nid lustre-mdt2/mdt2
	t_108_mkfs ost 0 zfs mgsnode=$nid lustre-ost1/ost1
	t_108_mkfs ost 1 zfs mgsnode=$nid lustre-ost2/ost2

	for facet in $facets; do
		$rcmd zfs set mountpoint=$tmp/mnt/$facet canmount=on \
			lustre-$facet/$facet ||
			error "failed to zfs set for $facet (1)"
		$rcmd zfs mount lustre-$facet/$facet ||
			error "failed to local mount $facet"
		$rcmd tar jxf $LUSTRE/tests/ldiskfs_${facet}_2_11.tar.bz2 \
			--xattrs --xattrs-include="trusted.*" \
			-C $tmp/mnt/$facet/ > /dev/null 2>&1 ||
			error "failed to untar image for $facet"
		$rcmd "cd $tmp/mnt/$facet && rm -rf oi.* OI_* lfsck_* LFSCK" ||
			error "failed to cleanup for $facet"
		$rcmd zfs umount lustre-$facet/$facet ||
			error "failed to local umount $facet"
		$rcmd zfs set canmount=off lustre-$facet/$facet ||
			error "failed to zfs set $facet (2)"
	done

	echo "changing server nid..."
	$rcmd mount -t lustre -o nosvc lustre-mdt1/mdt1 $tmp/mnt/mdt1
	$rcmd lctl replace_nids $FSNAME-MDT0000 $nid
	$rcmd lctl replace_nids $FSNAME-MDT0001 $nid
	$rcmd lctl replace_nids $FSNAME-OST0000 $nid
	$rcmd lctl replace_nids $FSNAME-OST0001 $nid
	$rcmd umount $tmp/mnt/mdt1

	for facet in $facets; do
		echo "mounting $facet from backup..."
		$rcmd mount -t lustre -o abort_recov lustre-$facet/$facet \
			$tmp/mnt/$facet || error "failed to mount $facet"
	done

	# ZFS backend can detect migration and trigger OI scrub automatically
	# sleep 3 seconds for scrub done
	sleep 3

	t_108_check
	t_108_cleanup
}
run_test 108a "migrate from ldiskfs to ZFS"

test_108b() {
	[ "$CLIENTONLY" ] && skip "Client-only testing"
	[ "$mds1_FSTYPE" != ldiskfs ] && skip "ldiskfs only test"
	[ "$MDS1_VERSION" -lt $(version_code 2.10.58) ] &&
		skip "Need server version at least 2.10.58"

	stopall
	load_modules

	local tmp=$TMP/$tdir
	local rcmd="do_facet $SINGLEMDS"
	local facets="mdt1 mdt2 ost1 ost2"
	local scrub_list="MDT0000 MDT0001 OST0000 OST0001"
	local nid=$($rcmd $LCTL list_nids | head -1)
	local facet

	trap t_108_cleanup EXIT ERR
	t_108_prep

	t_108_mkfs mdt 0 ldiskfs mgs
	t_108_mkfs mdt 1 ldiskfs mgsnode=$nid
	t_108_mkfs ost 0 ldiskfs mgsnode=$nid
	t_108_mkfs ost 1 ldiskfs mgsnode=$nid

	for facet in $facets; do
		$rcmd mount -t ldiskfs -o loop $tmp/images/$facet \
			$tmp/mnt/$facet ||
			error "failed to local mount $facet"

		$rcmd tar jxf $LUSTRE/tests/zfs_${facet}_2_11.tar.bz2 \
			--xattrs --xattrs-include="*.*" \
			-C $tmp/mnt/$facet/ > /dev/null 2>&1 ||
			error "failed to untar image for $facet"
		$rcmd "cd $tmp/mnt/$facet && rm -rf oi.* OI_* lfsck_* LFSCK" ||
			error "failed to cleanup for $facet"
		$rcmd umount $tmp/mnt/$facet ||
			error "failed to local umount $facet"
	done

	echo "changing server nid..."
	$rcmd mount -t lustre -o nosvc,loop $tmp/images/mdt1 $tmp/mnt/mdt1
	$rcmd lctl replace_nids $FSNAME-MDT0000 $nid
	$rcmd lctl replace_nids $FSNAME-MDT0001 $nid
	$rcmd lctl replace_nids $FSNAME-OST0000 $nid
	$rcmd lctl replace_nids $FSNAME-OST0001 $nid
	$rcmd umount $tmp/mnt/mdt1

	for facet in $facets; do
		echo "mounting $facet from backup..."
		$rcmd mount -t lustre -o loop,abort_recov $tmp/images/$facet \
			$tmp/mnt/$facet || error "failed to mount $facet"
	done

	for facet in $scrub_list; do
		$rcmd $LCTL lfsck_start -M $FSNAME-$facet -t scrub ||
			error "failed to start OI scrub on $facet"
	done

	# sleep 3 seconds for scrub done
	sleep 3

	t_108_check
	t_108_cleanup
}
run_test 108b "migrate from ZFS to ldiskfs"

#
# set number of permanent parameters
#
test_109_set_params() {
	local fsname=$1

	set_persistent_param_and_check mds			    \
	    "mdd.$fsname-MDT0000.atime_diff"			    \
	    "$fsname-MDT0000.mdd.atime_diff"			    \
	    "62"
	set_persistent_param_and_check mds			    \
	    "mdd.$fsname-MDT0000.atime_diff"			    \
	    "$fsname-MDT0000.mdd.atime_diff"			    \
	    "63"
	set_persistent_param_and_check client			    \
	    "llite.$fsname*.max_read_ahead_mb"			    \
	    "$fsname.llite.max_read_ahead_mb"			    \
	    "32"
	set_persistent_param_and_check client			    \
	    "llite.$fsname*.max_read_ahead_mb"			    \
	    "$fsname.llite.max_read_ahead_mb"                       \
	    "64"
	create_pool $fsname.pool1 || error "create pool failed"
	do_facet mgs $LCTL pool_add $fsname.pool1 OST0000 ||
		error "pool_add failed"
	do_facet mgs $LCTL pool_remove $fsname.pool1 OST0000 ||
		error "pool_remove failed"
	do_facet mgs $LCTL pool_add $fsname.pool1 OST0000 ||
		error "pool_add failed"
}

#
# check permanent parameters
#
test_109_test_params() {
	local fsname=$1

	local atime_diff=$(do_facet mds $LCTL \
		get_param -n mdd.$fsname-MDT0000.atime_diff)
	[ $atime_diff == 63 ] || error "wrong mdd parameter after clear_conf"
	local max_read_ahead_mb=$(do_facet client $LCTL \
		get_param -n llite.$fsname*.max_read_ahead_mb)
	[ $max_read_ahead_mb == 64 ] ||
		error "wrong llite parameter after clear_conf"
	local ost_in_pool=$(do_facet mds $LCTL pool_list $fsname.pool1 |
		grep -v "^Pool:" | sed 's/_UUID//')
	[ $ost_in_pool = "$fsname-OST0000" ] ||
		error "wrong pool after clear_conf"
}

#
# run lctl clear_conf, store CONFIGS before and after that
#
test_109_clear_conf()
{
	local clear_conf_arg=$1

	local mgsdev
	if ! combined_mgs_mds ; then
		mgsdev=$(mgsdevname)
		stop_mgs || error "stop_mgs failed"
		start_mgs "-o nosvc" || error "start_mgs nosvc failed"
	else
		mgsdev=$(mdsdevname 1)
		start_mdt 1 "-o nosvc" || error "start_mdt 1 nosvc failed"
	fi

	do_facet mgs "rm -rf $TMP/${tdir}/conf1; mkdir -p $TMP/${tdir}/conf1;" \
		"$DEBUGFS -c -R \\\"rdump CONFIGS $TMP/${tdir}/conf1\\\" \
		$mgsdev"

	#
	# the command being tested
	#
	do_facet mgs $LCTL clear_conf $clear_conf_arg ||
		error "clear_conf failed"
	if ! combined_mgs_mds ; then
		stop_mgs || error "stop_mgs failed"
	else
		stop_mdt 1 || error "stop_mdt 1 failed"
	fi

	do_facet mgs "rm -rf $TMP/${tdir}/conf2; mkdir -p $TMP/${tdir}/conf2;" \
		"$DEBUGFS -c -R \\\"rdump CONFIGS $TMP/${tdir}/conf2\\\" \
		$mgsdev"
}

test_109_file_shortened() {
	local file=$1
	local sizes=($(do_facet mgs "stat -c %s " \
		"$TMP/${tdir}/conf1/CONFIGS/$file" \
		"$TMP/${tdir}/conf2/CONFIGS/$file"))
	[ ${sizes[1]} -lt ${sizes[0]} ] && return 0
	return 1
}

test_109a()
{
	[ $MDS1_VERSION -lt $(version_code 2.10.59) ] &&
		skip "Needs MDS version 2.10.59 or later."
	[ "$(facet_fstype mgs)" == zfs ] &&
		skip "LU-8727: no implementation for ZFS"

	stopall
	reformat
	setup_noconfig
	client_up || error "client_up failed"

	#
	# set number of permanent parameters
	#
	test_109_set_params $FSNAME

	umount_client $MOUNT || error "umount_client failed"
	stop_ost || error "stop_ost failed"
	stop_mds || error "stop_mds failed"

	test_109_clear_conf $FSNAME
	#
	# make sure that all configs are cleared
	#
	test_109_file_shortened $FSNAME-MDT0000 ||
		error "failed to clear MDT0000 config"
	test_109_file_shortened $FSNAME-client ||
		error "failed to clear client config"

	setup_noconfig

	#
	# check that configurations are intact
	#
	test_109_test_params $FSNAME

	#
	# Destroy pool.
	#
	destroy_test_pools || error "destroy test pools failed"

	cleanup
}
run_test 109a "test lctl clear_conf fsname"

test_109b()
{
	[ $MDS1_VERSION -lt $(version_code 2.10.59) ] &&
		skip "Needs MDS version 2.10.59 or later."
	[ "$(facet_fstype mgs)" == zfs ] &&
		skip "LU-8727: no implementation for ZFS"

	stopall
	reformat
	setup_noconfig
	client_up || error "client_up failed"

	#
	# set number of permanent parameters
	#
	test_109_set_params $FSNAME

	umount_client $MOUNT || error "umount_client failed"
	stop_ost || error "stop_ost failed"
	stop_mds || error "stop_mds failed"

	test_109_clear_conf $FSNAME-MDT0000
	#
	# make sure that only one config is cleared
	#
	test_109_file_shortened $FSNAME-MDT0000 ||
		error "failed to clear MDT0000 config"
	test_109_file_shortened $FSNAME-client &&
		error "failed to clear client config"

	setup_noconfig
	#
	# check that configurations are intact
	#
	test_109_test_params $FSNAME

	#
	# Destroy pool.
	#
	destroy_test_pools || error "destroy test pools failed"

	cleanup
}
run_test 109b "test lctl clear_conf one config"

test_110()
{
	[[ "$mds1_FSTYPE" != ldiskfs ]] &&
		skip "Only applicable to ldiskfs-based MDTs"

	do_facet $SINGLEMDS $DEBUGFS -w -R supported_features |grep large_dir ||
		skip "large_dir option is not supported on MDS"
	do_facet ost1 $DEBUGFS -w -R supported_features | grep large_dir ||
		skip "large_dir option is not supported on OSS"

	stopall # stop all targets before modifying the target counts
	local old_mdscount=$MDSCOUNT
	local old_ostcount=$OSTCOUNT
	local replace=""
	stack_trap "MDSCOUNT=$old_mdscount OSTCOUNT=$old_ostcount" EXIT
	MDSCOUNT=1
	OSTCOUNT=1

	# ext4_dir_entry_2 struct size:264
	# dx_root struct size:8
	# dx_node struct size:8
	# dx_entry struct size:8
	# For 1024 bytes block size.
	# First level directory entries: 126
	# Second level directory entries: 127
	# Entries in leaf: 3
	# For 2 levels limit: 48006
	# For 3 levels limit : 6096762
	# Create 80000 files to safely exceed 2-level htree limit.
	CONF_SANITY_110_LINKS=${CONF_SANITY_110_LINKS:-80000}

	# can fit at most 3 filenames per 1KB leaf block, but each
	# leaf/index block will only be 3/4 full before split at each level
	(( MDSSIZE < CONF_SANITY_110_LINKS / 3 * 4/3 * 4/3 )) &&
		CONF_SANITY_110_LINKS=$((MDSSIZE * 3 * 3/4 * 3/4))

	combined_mgs_mds || replace=" --replace "
	local opts="$(mkfs_opts mds1 $(mdsdevname 1)) \
		    $replace --reformat $(mdsdevname 1) $(mdsvdevname 1)"
	if [[ $opts != *large_dir* ]]; then
		if [[ $opts != *mkfsoptions* ]]; then
			opts+=" --mkfsoptions=\\\"-O large_dir -b 1024 -i 65536\\\""
		else
			opts="${opts//--mkfsoptions=\\\"/ \
				--mkfsoptions=\\\"-O large_dir -b 1024 -i 65536 }"
		fi
	fi
	echo "MDT params: $opts"
	load_modules
	combined_mgs_mds || start_mgs
	add mds1 $opts || error "add mds1 failed with new params"
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS

	opts="$(mkfs_opts ost1 $(ostdevname 1)) \
		$replace --reformat $(ostdevname 1) $(ostvdevname 1)"

	if [[ $opts != *large_dir* ]]; then
		if [[ $opts != *mkfsoptions* ]]; then
			opts+=" --mkfsoptions=\\\"-O large_dir\\\" "
		else
			opts="${opts//--mkfsoptions=\\\"/ \
				--mkfsoptions=\\\"-O large_dir }"
		fi
	fi
	echo "OST params: $opts"
	add ost1 $opts || error "add ost1 failed with new params"
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS

	MOUNT_2=yes mountcli || error "mount clients failed"

	mkdir -v $DIR/$tdir || error "cannot create $DIR/$tdir"
	local pids count=0 group=0

	echo "creating $CONF_SANITY_110_LINKS in total"
	while (( count < CONF_SANITY_110_LINKS )); do
		local len=$((253 - $(wc -c <<<"$tfile-$group-40000-")))
		local dir=DIR$((group % 2 + 1))
		local target=${!dir}/$tdir/$tfile-$group
		local long=$target-$(generate_name $len)-
		local create=$((CONF_SANITY_110_LINKS - count))

		(( create > 40000 )) && create=40000
		touch $target || error "creating $target failed"
		echo "creating $create hard links to $target"
		createmany -l $target $long $create &
		pids+=" $!"

		count=$((count + create))
		group=$((group + 1))
	done
	echo "waiting for PIDs$pids to complete"
	wait $pids || error "createmany failed after $group groups"

	umount_client $MOUNT2 -f
	cleanup

	run_e2fsck $(facet_active_host mds1) $(mdsdevname 1) -n
	MDSCOUNT=$old_mdscount
	OSTCOUNT=$old_ostcount
}
run_test 110 "Adding large_dir with 3-level htree"

test_111() {
	[[ "$mds1_FSTYPE" != ldiskfs ]] &&
		skip "Only applicable to ldiskfs-based MDTs"

	is_dm_flakey_dev $SINGLEMDS $(mdsdevname 1) &&
		skip "This test can not be executed on flakey dev"

	do_facet $SINGLEMDS $DEBUGFS -w -R supported_features |grep large_dir ||
		skip "large_dir option is not supported on MDS"

	do_facet ost1 $DEBUGFS -w -R supported_features | grep large_dir ||
		skip "large_dir option is not supported on OSS"

	# cleanup before changing target counts
	cleanup
	local old_mdscount=$MDSCOUNT
	local old_ostcount=$OSTCOUNT
	local old_mdssize=$MDSSIZE
	local replace=""
	stack_trap "MDSSIZE=$MDSSIZE MDSCOUNT=$MDSCOUNT OSTCOUNT=$OSTCOUNT" EXIT
	MDSCOUNT=1
	OSTCOUNT=1
	(( MDSSIZE < 2400000 )) && MDSSIZE=2400000 # need at least 2.4GB

	local mdsdev=$(mdsdevname 1)
	combined_mgs_mds || replace=" --replace "
	local opts="$(mkfs_opts mds1 $(mdsdevname 1)) \
		    $replace --reformat $(mdsdevname 1) $(mdsvdevname 1)"
	if [[ $opts != *large_dir* ]]; then
		if [[ $opts != *mkfsoptions* ]]; then
			opts+=" --mkfsoptions=\\\"-O large_dir -i 1048576 \\\" "
		else
			opts="${opts//--mkfsoptions=\\\"/ \
				--mkfsoptions=\\\"-O large_dir -i 1048576 }"
		fi
	fi
	echo "MDT params: $opts"
	load_modules
	combined_mgs_mds || start_mgs
	__touch_device mds 1
	add mds1 $opts || error "add mds1 failed with new params"
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS

	opts="$(mkfs_opts ost1 $(ostdevname 1)) \
		$replace --reformat $(ostdevname 1) $(ostvdevname 1)"
	if [[ $opts != *large_dir* ]]; then
		if [[ $opts != *mkfsoptions* ]]; then
			opts+=" --mkfsoptions=\\\"-O large_dir \\\""
		else
			opts="${opts//--mkfsoptions=\\\"/ --mkfsoptions=\\\"-O large_dir }"
		fi
	fi
	echo "OST params: $opts"
	__touch_device ost 1
	add ost1 $opts || error "add ost1 failed with new params"
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS

	MOUNT_2=yes mountcli
	mkdir $DIR/$tdir || error "cannot create $DIR/$tdir"
	lfs df $DIR/$tdir
	lfs df -i $DIR/$tdir

	local group=0

	local start=$SECONDS
	local dirsize=0
	local dirmax=$((2 << 30))
	local needskip=0
	local taken=0
	local rate=0
	local left=0
	local num=0
	while (( !needskip & dirsize < dirmax )); do
		local pids=""

		for cli in ${CLIENTS//,/ }; do
			local len=$((253 - $(wc -c <<<"$cli-$group-60000-")))
			local target=$cli-$group
			local long=$DIR/$tdir/$target-$(generate_name $len)-

			RPWD=$DIR/$tdir do_node $cli touch $target ||
				error "creating $target failed"
			echo "creating 60000 hardlinks to $target"
			RPWD=$DIR/$tdir do_node $cli createmany -l $target $long 60000 &
			pids+=" $!"

			group=$((group + 1))
			target=$cli-$group
			long=$DIR2/$tdir/$target-$(generate_name $len)-

			RPWD=$DIR2/$tdir do_node $cli touch $target ||
				error "creating $target failed"
			echo "creating 60000 hardlinks to $target"
			RPWD=$DIR2/$tdir do_node $cli createmany -l $target $long 60000 &
			pids+=" $!"

			group=$((group + 1))
		done
		echo "waiting for PIDs$pids to complete"
		wait $pids || error "createmany failed after $group groups"
		dirsize=$(stat -c %s $DIR/$tdir)
		taken=$((SECONDS - start))
		rate=$((dirsize / taken))
		left=$(((dirmax - dirsize) / rate))
		num=$((group * 60000))
		echo "estimate ${left}s left after $num files / ${taken}s"
		# if the estimated time remaining is too large (it may change
		# over time as the create rate is not constant) then exit
		# without declaring a failure.
		(( left > 1200 )) && needskip=1
	done

	umount_client $MOUNT2 -f
	cleanup

	(( $needskip )) && skip "ETA ${left}s after $num files / ${taken}s is too long"

	run_e2fsck $(facet_active_host mds1) $(mdsdevname 1) -n
	MDSCOUNT=$old_mdscount
	OSTCOUNT=$old_ostcount
	MDSSIZE=$old_mdssize
}
run_test 111 "Adding large_dir with over 2GB directory"

test_112() {
	start_mds || error "MDS start failed"
	start_ost || error "OSS start failed"
	echo "start ost2 service on $(facet_active_host ost2)"
	start ost2 $(ostdevname 2) $(csa_add "$OST_MOUNT_OPTS" -o no_precreate) ||
		error "start ost2 facet failed"
	local val=$(do_facet ost2 \
		   "$LCTL get_param -n obdfilter.$FSNAME-OST0001*.no_precreate")
	(( $val == 1 )) || error "obdfilter.$FSNAME-OST0001*.no_precreate=$val"

	mount_client $MOUNT || error "mount client failed"
	wait_osc_import_state mds1 ost1 FULL
	wait_osc_import_state client ost1 FULL
	wait_osc_import_state client ost2 FULL

	$LFS setstripe -i 0 $DIR/$tfile.0 ||
		error "problem creating $tfile.0 on OST0000"
	$LFS setstripe -i 1 $DIR/$tfile.1 && $LFS getstripe $DIR/$tfile.1 &&
		(( $($LFS getstripe -i $DIR/$tfile.1) == 1 )) &&
		error "allowed to create $tfile.1 on OST0001"
	do_facet ost2 $LCTL set_param obdfilter.*.no_precreate=0
	sleep_maxage
	$LFS setstripe -i 1 $DIR/$tfile.2 ||
		error "failed to create $tfile.2 on ost1 facet"
	# files not cleaned with ONLY_REPEAT because of client unmount below
	rm -f $DIR/$tfile.[012]
	stop_ost2 || error "stop ost2 facet failed"
	cleanup
}
run_test 112 "mount OST with nocreate option"

cleanup_115()
{
	trap 0
	stopall
	rm -f $TMP/$tdir/lustre-mdt
}

test_115() {
	if [ "$mds1_FSTYPE" != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
	fi
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"

	local dbfs_ver=$(do_facet $SINGLEMDS $DEBUGFS -V 2>&1)

	echo "debugfs version: $dbfs_ver"
	echo "$dbfs_ver" | egrep -w "1.44.3.wc1|1.44.5.wc1|1.45.2.wc1" &&
		skip_env "This version of debugfs doesn't show inode number"

	is_dm_flakey_dev $SINGLEMDS $(mdsdevname 1) &&
		skip "This test can not be executed on flakey dev"

	IMAGESIZE=$((3072 << 30)) # 3072 GiB

	stopall

	echo "client1: "
	lctl dl
	mount | grep lustre
	echo "mds1: "
	do_facet mds1 "hostname; ifconfig; lctl dl; mount"
	echo "ost1: "
	do_facet ost1 "hostname; ifconfig; lctl dl; mount"
	# We need MDT size 3072GB, because it is smallest
	# partition that can store 2B inodes
	do_facet $SINGLEMDS "mkdir -p $TMP/$tdir"
	local mdsimgname=$TMP/$tdir/lustre-mdt
	do_facet $SINGLEMDS "rm -f $mdsimgname"
	do_facet $SINGLEMDS "touch $mdsimgname"
	trap cleanup_115 RETURN EXIT
	do_facet $SINGLEMDS "$TRUNCATE $mdsimgname $IMAGESIZE" ||
		skip "Backend FS doesn't support sparse files"
	local mdsdev=$(do_facet $SINGLEMDS "losetup -f")
	do_facet $SINGLEMDS "losetup $mdsdev $mdsimgname"

	local mds_opts="$(mkfs_opts mds1 $(mdsdevname 1))	 \
		--mkfsoptions='-O ea_inode,^resize_inode,meta_bg \
		-N 2247484000 -E lazy_itable_init' --device-size=$IMAGESIZE"
	add mds1 $mds_opts --mgs --reformat $mdsdev ||
		skip_env "format large MDT failed"
	opts="$(mkfs_opts ost1 $(ostdevname 1)) \
		$replace --reformat $(ostdevname 1) $(ostvdevname 1)"
	add ost1 $opts || error "add ost1 failed with new params"
	start $SINGLEMDS  $mdsdev $MDS_MOUNT_OPTS || error "start MDS failed"
	start_ost || error "start OSS failed"
	mount_client $MOUNT || error "mount client failed"

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir fail"
	goal="/sys/fs/ldiskfs/$(basename $mdsdev)/inode_goal"
echo goal: $goal
	# 2147483648 is 0x80000000
	do_facet $SINGLEMDS "echo 2147483648 >> $goal; grep . $goal"
	touch $DIR/$tdir/$tfile

	# attrs from 1 to 15 go to block, 16th - to inode
	for i in {1..16}; do
		local nm="trusted.ea$i"
		setfattr -n $nm -v $(printf "xattr%0250d" $i) $DIR/$tdir/$tfile
	done

	# inode <2147483649> trusted.ea16 (255)
	local inode_num=$(do_facet $SINGLEMDS \
			"$DEBUGFS -c -R 'stat ROOT/$tdir/$tfile' $mdsdev" |
			 awk '/ea16/ { print $2 }' |
			 sed -e 's/>//' -e 's/<//' -e 's/\"//')
	echo "inode num: $inode_num"
	[ $inode_num -ge 2147483648 ] || error "inode $inode_num too small"
	do_facet $SINGLEMDS "losetup -d $mdsdev"
	cleanup_115
}
run_test 115 "Access large xattr with inodes number over 2TB"

test_116() {
	[ "$mds1_FSTYPE" != ldiskfs ] && skip "ldiskfs only test"
	[ "$MDS1_VERSION" -lt $(version_code 2.10.59) ] &&
		skip "Need server version at least 2.10.59"
	do_facet $SINGLEMDS which mkfs.xfs ||
		skip_env "No mkfs.xfs installed"

	stopall
	load_modules

	local tmpmnt=$TMP/$tdir
	local mdtimg=$tfile-mdt0

	do_facet $SINGLEMDS mkdir -p $tmpmnt
	stack_trap "do_facet $SINGLEMDS rmdir $tmpmnt" EXIT

	do_facet $SINGLEMDS touch $TMP/$mdtimg
	stack_trap "do_facet $SINGLEMDS rm -f $TMP/$mdtimg" EXIT
	do_facet $SINGLEMDS mkfs -t xfs -d file,size=1t,name=$TMP/$mdtimg ||
		error "mkfs temporary xfs image"

	do_facet $SINGLEMDS mount $TMP/$mdtimg $tmpmnt ||
		error "mount temporary xfs image"
	stack_trap "do_facet $SINGLEMDS umount $tmpmnt" EXIT
	local old_mdssize=$MDSSIZE
	local old_mdsisize=$MDSISIZE

	MDSSIZE=$((17 * 1024 * 1024 * 1024)) # 17T MDT
	MDSISIZE=$((16 << 20))
	local opts17t="$(mkfs_opts $SINGLEMDS)"

	MDSSIZE=$old_mdssize
	MDSISIZE=$old_mdsisize

	do_facet $SINGLEMDS $MKFS \
		${opts17t/-E /-E lazy_itable_init,lazy_journal_init,} \
		$tmpmnt/$mdtimg ||
		error "failed to mkfs for $tmpmnt/$mdtimg"

	do_facet $SINGLEMDS $TUNE2FS -l $tmpmnt/$mdtimg |
		grep -qw 'features.*extent' || error "extent should be enabled"
	reformat_and_config
}
run_test 116 "big size MDT support"

test_117() {
	setup
	do_facet ost1 "$LCTL set_param ost.OSS.ost_io.nrs_policies=fifo"
	do_facet ost1 "$LCTL get_param -n ost.OSS.ost_io.nrs_tbf_rule" &&
		error "get_param should fail"
	cleanup || error "cleanup failed with rc $?"
}
run_test 117 "lctl get_param return errors properly"

test_119() {
	local had_config
	local size_mb

	[[ "$MDSCOUNT" -ge 2 ]] || skip "Need more at least 2 MDTs"

	had_config=$(do_facet mds1 "$LCTL get_param debug | grep config")
	do_facet mds1 "$LCTL set_param debug=+config"
	do_facet mds1 "$LCTL clear"

	setup
	do_facet mds2 "$TUNEFS --writeconf $(mdsdevname 2)" &>/dev/null
	# mount after writeconf will make "add osp" added to mdt0 config:
	# 53 (224)marker  60 (flags=0x01, v2.5.1.0) lustre-MDT0001  'add osp'
	# 54 (080)add_uuid  nid=...  0:  1:...
	# 55 (144)attach    0:lustre-MDT0001-osp-MDT0000  1:osp  2:...
	# 56 (144)setup     0:lustre-MDT0001-osp-MDT0000  1:...  2:...
	# 57 (136)modify_mdc_tgts add 0:lustre-MDT0000-mdtlov  1:...  2:1  3:1
	# duplicate modify_mdc_tgts caused crashes

	debug_size_save
	# using larger debug_mb size to avoid lctl dk log truncation
	size_mb=$((DEBUG_SIZE_SAVED * 4))
	for i in {1..3}; do
		stop_mdt 2
		# though config processing stops after failed attach and setup
		# it will proceed after the failed command after each writeconf
		# this is the original scenario of the issue
		do_facet mds2 "$TUNEFS --writeconf $(mdsdevname 2)" &>/dev/null
		do_facet mds1 "$LCTL set_param debug_mb=$size_mb"
		start_mdt 2

		wait_update_facet_cond mds1 \
			"$LCTL dk | grep -c Processed.log.$FSNAME-MDT0000" \
			">" 1 300
	done
	debug_size_restore

	[[ -z "$had_config" ]] && do_facet mds1 lctl set_param debug=-config

	reformat
}
run_test 119 "writeconf on slave mdt shouldn't duplicate mdc/osp and crash"

test_120() { # LU-11130
	[ "$MDSCOUNT" -lt 2 ] && skip "mdt count < 2"
	[ "$mds1_FSTYPE" != ldiskfs ] &&
		skip "ldiskfs only test"
	[ "$MDS1_VERSION" -lt $(version_code 2.11.56) ] &&
		skip "Need DNE2 capable MD target with LU-11130 fix"

	setup

	local mds1host=$(facet_active_host mds1)
	local mds1dev=$(mdsdevname 1)

	$LFS mkdir -i 1 $DIR/$tdir
	$LFS mkdir -i 0 $DIR/$tdir/mds1dir

	ln -s foo $DIR/$tdir/bar
	mv $DIR/$tdir/bar $DIR/$tdir/mds1dir/bar2 ||
		error "cross-target rename failed"

	stopall

	run_e2fsck $mds1host $mds1dev "-n"
}
run_test 120 "cross-target rename should not create bad symlinks"

test_122a() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	[[ "$OST1_VERSION" -ge $(version_code 2.11.53) ]] ||
		skip "Need OST version at least 2.11.53"

	reformat
	LOAD_MODULES_REMOTE=true load_modules
#define OBD_FAIL_OFD_SET_OID 0x1e0
	do_facet ost1 $LCTL set_param fail_loc=0x00001e0

	setup_noconfig
	$LFS mkdir -i1 -c1 $DIR/$tdir
	$LFS setstripe -i0 -c1 $DIR/$tdir
	do_facet ost1 $LCTL set_param fail_loc=0
	createmany -o $DIR/$tdir/file_ 1000 ||
		error "Fail to create a new sequence"

	cleanup
}
run_test 122a "Check OST sequence update"

test_122b() {
	[[ "$OST1_VERSION" -ge $(version_code 2.11.53) ]] ||
		skip "Need OST version at least 2.11.53"
	local err

	reformat
	LOAD_MODULES_REMOTE=true load_modules
#define OBD_FAIL_OFD_SET_OID 0x1e0
	do_facet ost1 $LCTL set_param fail_loc=0x00001e0

	stack_trap cleanup EXIT
	setup_noconfig
	do_facet ost1 $LCTL set_param obdfilter.*.precreate_batch=256
	$LFS mkdir -i0 -c1 $DIR/$tdir || error "failed to create directory"
	$LFS setstripe -i0 -c1 $DIR/$tdir || error "failed to setstripe"
	do_facet ost1 $LCTL set_param fail_loc=0
	# overflow IDIF 32bit and create > OST_MAX_PRECREATE*5
	# so a new wrong sequence would differ from an original with error
	#define OST_MAX_PRECREATE 20000
	local ost_max_precreate=20100
	local num_create=$(( ost_max_precreate * 5 ))

	# Check the number of inodes available on OST0
	local files=0
	local ifree=$($LFS df -i $MOUNT |
		awk '/OST0000/ { print $4 }'; exit ${PIPESTATUS[0]})

	log "On OST0, $ifree inodes available. Want $num_create. rc=$?"

	if [ $ifree -lt 10000 ]; then
		files=$(( ifree - 50 ))
	else
		files=10000
	fi

	local j=$((num_create / files + 1))

	for i in $(seq 1 $j); do
		createmany -o $DIR/$tdir/$tfile-$i- $files ||
			error "createmany fail create $files files: $?"
		unlinkmany $DIR/$tdir/$tfile-$i- $files ||
			error "unlinkmany failed unlink $files files"
	done
	sync
	do_facet ost1 sync
	#we need a write req during recovery for ofd_seq_load
	replay_barrier ost1
	dd if=/dev/urandom of=$DIR/$tdir/$tfile bs=1024k count=1 oflag=sync ||
		 error "failed to write file"

	# OBD_FAIL_OST_CREATE_NET 0x204
	do_facet ost1 $LCTL set_param fail_loc=0x80000204
	fail ost1
	createmany -o $DIR/$tdir/file_ 100
	sync

	err=$(do_facet ost1 dmesg | tac | sed "/Recovery over/,$ d" |
	      grep "OST replaced or reformatted")
	[ -z "$err" ] || error $err
}
run_test 122b "Check OST sequence wouldn't change when IDIF 32bit overflows"

test_123aa() {
	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ -d $MOUNT/.lustre ] || setup

	# test old logid format until removal from llog_ioctl.c::str2logid()
	if [ $MGS_VERSION -lt $(version_code 3.1.53) ]; then
		do_facet mgs $LCTL dl | grep MGS
		do_facet mgs "$LCTL --device %MGS llog_print \
			      \\\\\\\$$FSNAME-client 1 10" ||
			error "old llog_print failed"
	fi

	# test new logid format
	if [ $MGS_VERSION -ge $(version_code 2.9.53) ]; then
		do_facet mgs "$LCTL --device MGS llog_print $FSNAME-client" ||
			error "new llog_print failed"
	fi
}
run_test 123aa "llog_print works with FIDs and simple names"

test_123ab() {
	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[[ $MGS_VERSION -gt $(version_code 2.11.51) ]] ||
		skip "Need server with working llog_print support"

	[ -d $MOUNT/.lustre ] || setup

	local yaml
	local orig_val
	local mgs_arg=""

	[[ $MGS_VERSION -gt $(version_code 2.13.54) ]] ||
		mgs_arg="--device MGS"

	orig_val=$(do_facet mgs $LCTL get_param jobid_name)
	do_facet mgs $LCTL set_param -P jobid_name="TESTNAME"

	yaml=$(do_facet mgs $LCTL $mgs_arg llog_print params |
	       grep jobid_name | tail -n 1)

	local param=$(awk '{ print $10 }' <<< "$yaml")
	local val=$(awk '{ print $12 }' <<< "$yaml")
	#return to the default
	do_facet mgs $LCTL set_param -P jobid_name=$orig_val
	[ $val = "TESTNAME" ] || error "bad value: $val"
	[ $param = "jobid_name," ] || error "Bad param: $param"
}
run_test 123ab "llog_print params output values from set_param -P"

test_123ac() { # LU-11566
	remote_mgs_nodsh && skip "remote MGS with nodsh"
	do_facet mgs "$LCTL help llog_print" 2>&1 | grep -q -- --start ||
		skip "Need 'lctl llog_print --start' on MGS"

	local start=10
	local end=50
	local mgs_arg=""

	[[ $MGS_VERSION -gt $(version_code 2.13.54) ]] ||
		mgs_arg="--device MGS"

	[ -d $MOUNT/.lustre ] || setup

	# - { index: 10, event: add_uuid, nid: 192.168.20.1@tcp(0x20000c0a81401,
	#     node: 192.168.20.1@tcp }
	do_facet mgs $LCTL $mgs_arg \
		llog_print --start $start --end $end $FSNAME-client | tr -d , |
		while read DASH BRACE INDEX idx EVENT BLAH BLAH BLAH; do
		(( idx >= start )) || error "llog_print index $idx < $start"
		(( idx <= end )) || error "llog_print index $idx > $end"
	done
}
run_test 123ac "llog_print with --start and --end"

test_123ad() { # LU-11566
	remote_mgs_nodsh && skip "remote MGS with nodsh"
	# older versions of lctl may not print all records properly
	do_facet mgs "$LCTL help llog_print" 2>&1 | grep -q -- --start ||
		skip "Need 'lctl llog_print --start' on MGS"

	[ -d $MOUNT/.lustre ] || setup

	# append a new record, to avoid issues if last record was cancelled
	local old=$($LCTL get_param -n osc.*-OST0000-*.max_dirty_mb | head -1)
	do_facet mgs $LCTL conf_param $FSNAME-OST0000.osc.max_dirty_mb=$old

	# logid:            [0x3:0xa:0x0]:0
	# flags:            4 (plain)
	# records_count:    72
	# last_index:       72
	local num=$(do_facet mgs $LCTL --device MGS llog_info $FSNAME-client |
		    awk '/last_index:/ { print $2 - 1 }')

	# - { index: 71, event: set_timeout, num: 0x14, param: sys.timeout=20 }
	local last=$(do_facet mgs $LCTL --device MGS llog_print $FSNAME-client |
		     tail -1 | awk '{ print $4 }' | tr -d , )
	(( last == num )) || error "llog_print only showed $last/$num records"
}
run_test 123ad "llog_print shows all records"

test_123ae() { # LU-11566
	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ -d $MOUNT/.lustre ] || setupall

	local max=$($LCTL get_param -n osc.*-OST0000-*.max_dirty_mb | head -1)
	local mgs_arg=""

	[[ $MGS_VERSION -gt $(version_code 2.13.54) ]] ||
		mgs_arg="--device MGS"

	if do_facet mgs "$LCTL help llog_cancel" 2>&1| grep -q -- --log_id; then
		# save one set_param -P record in case none exist
		do_facet mgs $LCTL set_param -P osc.*.max_dirty_mb=$max

		local log=params
		local orig=$(do_facet mgs $LCTL $mgs_arg llog_print $log |
			     tail -1 | awk '{ print $4 }' | tr -d , )
		do_facet mgs $LCTL set_param -P osc.*.max_dirty_mb=$max
		do_facet mgs $LCTL $mgs_arg llog_print $log | tail -1 |
			grep "parameter: osc.*.max_dirty_mb" ||
			error "new set_param -P wasn't stored in params log"

		# - { index: 71, event: set_param, device: general,
		#     param: osc.*.max_dirty_mb, value: 256 }
		local id=$(do_facet mgs $LCTL $mgs_arg llog_print $log |
			   tail -1 | awk '{ print $4 }' | tr -d , )

		do_facet mgs $LCTL $mgs_arg llog_cancel $log --log_idx=$id
		local new=$(do_facet mgs $LCTL $mgs_arg llog_print $log |
			    tail -1 | awk '{ print $4 }' | tr -d , )
		(( new == orig )) ||
			error "new llog_cancel now $new, not at $orig records"
	fi

	# test old positional parameters for a while still
	if [ "$MGS_VERSION" -le $(version_code 3.1.53) ]; then
		log=$FSNAME-client
		orig=$(do_facet mgs $LCTL --device MGS llog_print $log |
		       tail -1 | awk '{ print $4 }' | tr -d , )
		do_facet mgs $LCTL conf_param $FSNAME-OST0000.osc.max_dirty_mb=$max
		do_facet mgs $LCTL --device MGS llog_print $log |
			tail -1 | grep "parameter: osc.max_dirty_mb" ||
			error "old conf_param wasn't stored in params log"

		# - { index: 71, event: conf_param, device: testfs-OST0000-osc,
		#     param: osc.max_dirty_mb=256 }
		id=$(do_facet mgs $LCTL --device MGS llog_print $log |
		     tail -1 | awk '{ print $4 }' | tr -d , )
		do_facet mgs $LCTL --device MGS llog_cancel $log $id
		new=$(do_facet mgs $LCTL --device MGS llog_print $log |
		      tail -1 | awk '{ print $4 }' | tr -d , )
		(( new == orig )) ||
			error "old llog_cancel now $new, not at $orig records"
	fi
}
run_test 123ae "llog_cancel can cancel requested record"

test_123af() { #LU-13609
	[ "$MGS_VERSION" -ge $(version_code 2.13.54) -a \
	   "$MDS1_VERSION" -ge $(version_code 2.13.54) ] ||
		skip "Need both MGS and MDS version at least 2.13.54"

	[ -d $MOUNT/.lustre ] || setupall
	stack_trap "do_facet mds1 $LCTL set_param fail_loc=0" EXIT

	local device
	local facet
	local cmd
	local orig_clist
	local orig_count
	local new_clist
	local new_count

	for device in "MGS" "$FSNAME-MDT0000"; do
		cmd="--device $device llog_catlist"
		echo "lctl $cmd ..."
		if [ "$device" = "MGS" ]; then
			facet="mgs"
		else
			facet="mds1"
		fi
		orig_clist=($(do_facet $facet $LCTL $cmd | awk '{ print $2 }'))
		orig_count=${#orig_clist[@]}
		echo "orig_clist: ${orig_clist[@]}"

		#define OBD_FAIL_CATLIST 0x131b
		#fetch to llog records from the second one
		do_facet $facet $LCTL set_param fail_loc=0x131b fail_val=2

		new_clist=($(do_facet $facet $LCTL $cmd | awk '{ print $2 }'))
		new_count=${#new_clist[@]}
		echo "new_clist: ${new_clist[@]}"

		[ $new_count -eq $((orig_count - 1)) ] ||
			error "$new_count != $orig_count - 1"
		for i in $(seq 0 $new_count); do
			j=$((i + 1))
			[ "${orig_clist[$j]}" = "${new_clist[$i]}" ] ||
				error "${orig_clist[$j]} != ${new_clist[$i]}"
		done
		do_facet mds1 $LCTL set_param fail_loc=0
		echo "done"
	done
}
run_test 123af "llog_catlist can show all config files correctly"

test_123F() {
	remote_mgs_nodsh && skip "remote MGS with nodsh"

	[ -d $MOUNT/.lustre ] || setup
	local yaml_file="$TMP/$tfile.yaml"
	do_facet mgs rm "$yaml_file"
	local cfgfiles=$(do_facet mgs "lctl --device MGS llog_catlist" |
			 sed 's/config_log://')

	# set jobid_var to a different value for test
	local orig_val=$(do_facet mgs $LCTL get_param jobid_var)
	do_facet mgs $LCTL set_param -P jobid_var="TESTNAME"

	for i in $cfgfiles params; do
		do_facet mgs "lctl --device MGS llog_print ${i} >> $yaml_file"
	done

	echo "Unmounting FS"
	stopall
	echo "Writeconf"
	writeconf_all
	echo "Remounting"
	mountmgs
	mountmds
	mountoss
	mountcli

	# Reapply the config from before
	echo "Setting configuration parameters"
	do_facet mgs "lctl set_param -F $yaml_file"

	local set_val=$(do_facet mgs $LCTL get_param jobid_var)
	do_facet mgs $LCTL set_param -P $orig_val

	[ $set_val == "jobid_var=TESTNAME" ] ||
		error "$set_val is not TESTNAME"

	do_facet mgs rm "$yaml_file"
	cleanup
}
run_test 123F "clear and reset all parameters using set_param -F"

test_124()
{
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	[ -z $mds2failover_HOST ] && skip "needs MDT failover setup"

	setup
	do_facet mgs $LCTL --device MGS llog_print $FSNAME-client |
		grep 1.2.3.4@tcp && error "Should not be fake nid"
	do_facet mgs $LCTL conf_param $FSNAME-MDT0001.failover.node=1.2.3.4@tcp\
		|| error "Set params error"
	do_facet mgs $LCTL --device MGS llog_print $FSNAME-client |
		grep 1.2.3.4@tcp || error "Fake nid should be added"
	cleanup

	load_modules
	if combined_mgs_mds; then
		start_mdt 1 "-o nosvc" ||
			error "starting mds with nosvc option failed"
	fi
	local nid=$(do_facet mds2 $LCTL list_nids | head -1)
	local failover_nid=$(do_node $mds2failover_HOST $LCTL list_nids | head -1)
	do_facet mgs $LCTL replace_nids $FSNAME-MDT0001 $nid:$failover_nid ||
		error "replace_nids execution error"

	if combined_mgs_mds; then
		stop_mdt 1
	fi

	setup
	fail mds2
	echo "lfs setdirstripe"
	$LFS setdirstripe -i 1 $MOUNT/$tdir || error "setdirstirpe error"
	echo ok
}
run_test 124 "check failover after replace_nids"

get_max_sectors_kb() {
	local facet="$1"
	local device="$2"
	local dev_base=$(basename $(do_facet ${facet} "readlink -f ${device}"))
	local max_sectors_path="/sys/block/${dev_base}/queue/max_sectors_kb"

	do_facet ${facet} "[[ -e ${max_sectors_path} ]] &&
			   cat ${max_sectors_path}"
}

get_max_hw_sectors_kb() {
	local facet="$1"
	local device="$2"
	local dev_base=$(basename $(do_facet ${facet} "readlink -f ${device}"))
	local max_hw_path="/sys/block/${dev_base}/queue/max_hw_sectors_kb"

	do_facet ${facet} "[[ -e ${max_hw_path} ]] && cat ${max_hw_path}"
}

set_max_sectors_kb() {
	local facet="$1"
	local device="$2"
	local value="$3"
	local dev_base=$(basename $(do_facet ${facet} "readlink -f ${device}"))
	local max_sectors_path="/sys/block/${dev_base}/queue/max_sectors_kb"

	do_facet ${facet} "[[ -e ${max_sectors_path} ]] &&
			   echo ${value} > ${max_sectors_path}"
	rc=$?

	[[ $rc -ne 0 ]] && echo "Failed to set ${max_sectors_path} to ${value}"

	return $rc
}

# Return 0 if all slave devices have max_sectors_kb == max_hw_sectors_kb
# Otherwise return > 0
check_slaves_max_sectors_kb()
{
	local facet="$1"
	local device="$2"
	local dev_base=$(basename $(do_facet ${facet} "readlink -f ${device}"))
	local slaves_dir=/sys/block/${dev_base}/slaves
	local slave_devices=$(do_facet ${facet} "ls ${slaves_dir} 2>/dev/null")
	[[ -z ${slave_devices} ]] && return 0

	local slave max_sectors new_max_sectors max_hw_sectors path
	local rc=0
	for slave in ${slave_devices}; do
		path="/dev/${slave}"
		! is_blkdev ${facet} ${path} && continue
		max_sectors=$(get_max_sectors_kb ${facet} ${path})
		max_hw_sectors=$(get_max_hw_sectors_kb ${facet} ${path})
		new_max_sectors=${max_hw_sectors}
		[[ ${new_max_sectors} -gt ${RQ_SIZE_LIMIT} ]] &&
			new_max_sectors=${RQ_SIZE_LIMIT}

		if [[ ${max_sectors} -ne ${new_max_sectors} ]]; then
			echo "${path} ${max_sectors} ${new_max_sectors}"
			((rc++))
		fi
		check_slaves_max_sectors_kb ${facet} ${path}
		((rc + $?))
	done

	return $rc
}

test_125()
{
	local facet_list="mgs mds1 ost1"
	combined_mgs_mds && facet_list="mgs ost1"

	local facet
	for facet in ${facet_list}; do
		[[ $(facet_fstype ${facet}) != ldiskfs ]] &&
			skip "ldiskfs only test" &&
			return 0
		! is_blkdev ${facet} $(facet_device ${facet}) &&
			skip "requires all real devices" &&
			return 0
	done

	local rc=0
	# We don't increase IO request size limit past 16MB. See comments in
	# lustre/utils/libmount_utils_ldiskfs.c:tune_max_sectors_kb()
	RQ_SIZE_LIMIT=$((16 * 1024))
	local device old_max_sectors new_max_sectors max_hw_sectors
	for facet in ${facet_list}; do
		device=$(facet_device ${facet})
		old_max_sectors=$(get_max_sectors_kb ${facet} ${device})
		max_hw_sectors=$(get_max_hw_sectors_kb ${facet} ${device})

		# The expected value after l_tunedisk is executed
		new_max_sectors=$old_max_sectors
		[[ ${new_max_sectors_kb} -gt ${RQ_SIZE_LIMIT} ]] &&
			new_max_sectors_kb=${RQ_SIZE_LIMIT}

		# Ensure the current value of max_sectors_kb does not equal
		# max_hw_sectors_kb, so we can tell whether l_tunedisk did
		# anything
		set_max_sectors_kb ${facet} ${device} $((new_max_sectors - 1))

		# Value before l_tunedisk
		local pre_max_sectors=$(get_max_sectors_kb ${facet} ${device})
		if [[ ${pre_max_sectors} -ne $((new_max_sectors - 1)) ]]; then
			echo "unable to satsify test pre-condition:"
			echo "${pre_max_sectors} != $((new_max_sectors - 1))"
			((rc++))
			continue
		fi

		echo "Before: ${facet} ${device} ${pre_max_sectors} ${max_hw_sectors}"

		do_facet ${facet} "l_tunedisk ${device}"

		# Value after l_tunedisk
		local post_max_sectors=$(get_max_sectors_kb ${facet} ${device})

		echo "After: ${facet} ${device} ${post_max_sectors} ${max_hw_sectors}"

		if [[ ${facet} != ost1 ]]; then
			if [[ ${post_max_sectors} -ne ${pre_max_sectors} ]]; then
				echo "l_tunedisk modified max_sectors_kb of ${facet}"
				((rc++))
			fi

			set_max_sectors_kb ${facet} ${device} ${old_max_sectors}
		else
			if [[ ${post_max_sectors} -eq ${pre_max_sectors} ]]; then
				echo "l_tunedisk failed to modify max_sectors_kb of ${facet}"
				((rc++))
			fi

			check_slaves_max_sectors_kb ${facet} ${device} ||
				((rc++))
		fi
	done

	return $rc
}
run_test 125 "check l_tunedisk only tunes OSTs and their slave devices"

test_126() {
	[[ "$MDS1_VERSION" -ge $(version_code 2.13.52) ]] ||
		skip "Need MDS version at least 2.13.52"

	cleanup
	do_rpc_nodes $(facet_active_host $SINGLEMDS) load_module ../libcfs/libcfs/libcfs
	#define OBD_FAIL_OBD_SETUP 0x60d
	do_facet mds1 $LCTL set_param fail_loc=0x60d
	do_rpc_nodes $(facet_active_host $SINGLEMDS) load_modules &
	for i in {1..40}; do
		do_facet mds1 lsmod | grep -q osd_$mds1_FSTYPE && break
		sleep 1
	done
	clear_failloc $SINGLEMDS 20 &
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS
}
run_test 126 "mount in parallel shouldn't cause a crash"

test_127() {
	[[ "$ost1_FSTYPE" == ldiskfs ]] || skip "ldiskfs only test"

	cleanup
	setup
	zconf_umount_clients $RCLIENTS $MOUNT

	wait_osp_active ost ${FSNAME}-OST0000 0 1
	local osc_tgt="$FSNAME-OST0000-osc-$($LFS getname -i $DIR)"
	local avail1=($($LCTL get_param -n osc.${osc_tgt}.kbytesavail))

	$LFS setstripe -i 0 $DIR/$tfile || error "failed creating $DIR/$tfile"
	dd if=/dev/zero of=$DIR/$tfile bs=1M oflag=direct || true

	local avail2=($($LCTL get_param -n osc.${osc_tgt}.kbytesavail))

	if ((avail2 * 100 / avail1 > 1)); then
		lfs df $DIR
		ls -l $DIR/$tfile
		error "more than 1% space left: before=$avail1 after=$avail2"
	fi

	local mbs=$(($(stat -c %s $DIR/$tfile) / (1024 * 1024)))

	dd if=/dev/zero of=$DIR/$tfile bs=1M count=$mbs conv=notrunc \
		oflag=direct || error "overwrite failed"
}
run_test 127 "direct io overwrite on full ost"

test_128()
{
	combined_mgs_mds && skip "need separate mgs device"
	[ "$ost2_FSTYPE" == zfs ] && import_zpool ost2

	format_ost 2
	# Try to apply nolocallogs to the virgin OST. Should fail.
	do_facet ost2 "$TUNEFS --nolocallogs $(ostdevname 2)" &&
		error "nolocallogs should not be allowed on the virgin target"

	setupall
	stopall

	[ "$ost1_FSTYPE" == zfs ] && import_zpool ost1
	# Start OST without MGS (local configs)
	do_facet ost1 "$TUNEFS --dryrun $(ostdevname 1)"
	start_ost || error "unable to start OST1"
	stop_ost || error "Unable to stop OST1"

	[ "$ost1_FSTYPE" == zfs ] && import_zpool ost1
	# Do not allow reading local configs, should fail
	do_facet ost1 "$TUNEFS --nolocallogs $(ostdevname 1)" ||
		error "Can not set nolocallogs"
	start_ost && error "OST1 started, but should fail"

	# Connect to MGS successfully, reset nolocallogs flag
	[ "$ost1_FSTYPE" == zfs ] && import_zpool ost1
	start_mgs || error "unable to start MGS"
	start_ost || error "unable to start OST1"

	do_facet ost1 "$TUNEFS --dryrun $(ostdevname 1)" | grep "nolocallogs" &&
		error "nolocallogs expected to be reset"

	stop_ost || error "Unable to stop OST1"
}
run_test 128 "Force using remote logs with --nolocallogs"

test_130()
{
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	setupall
	stop_mdt 2 || error "mdt2 stop failed"
	do_facet mds2 "$TUNEFS --writeconf $(mdsdevname 2)"
	start_mdt 2 || error "mdt2 start failed"
	do_facet mds2 "$LCTL dl" | grep MDT0001-osp-MDT0001 &&
		error "Illegal OSP device created" || true
}
run_test 130 "re-register an MDT after writeconf"

if ! combined_mgs_mds ; then
	stop mgs
fi

cleanup_gss

# restore the values of MDSSIZE and OSTSIZE
MDSSIZE=$STORED_MDSSIZE
OSTSIZE=$STORED_OSTSIZE
reformat

complete $SECONDS
check_and_cleanup_lustre
exit_status
