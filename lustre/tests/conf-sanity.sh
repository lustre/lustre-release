#!/bin/bash

set -e

ONLY=${ONLY:-"$*"}

# bug number for skipped test:     LU-2828
ALWAYS_EXCEPT="$CONF_SANITY_EXCEPT 59 64"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

is_sles11()						# LU-2181
{
	if [ -r /etc/SuSE-release ]
	then
		local vers=$(grep VERSION /etc/SuSE-release | awk '{print $3}')
		local patchlev=$(grep PATCHLEVEL /etc/SuSE-release |
			awk '{ print $3 }')
		if [ $vers -eq 11 ] && [ $patchlev -eq 2 ]
		then
			return 0
		fi
	fi
	return 1
}

if is_sles11; then					# LU-2181
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 23a 34b"
fi

if [ "$FAILURE_MODE" = "HARD" ]; then
	CONFIG_EXCEPTIONS="24a " &&
	echo "Except the tests: $CONFIG_EXCEPTIONS for " \
	     "FAILURE_MODE=$FAILURE_MODE, b=23573" &&
		ALWAYS_EXCEPT="$ALWAYS_EXCEPT $CONFIG_EXCEPTIONS"
fi

# bug number for skipped test:
# a tool to create lustre filesystem images
ALWAYS_EXCEPT="32newtarball $ALWAYS_EXCEPT"

SRCDIR=$(dirname $0)
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

PTLDEBUG=${PTLDEBUG:--1}
SAVE_PWD=$PWD
LUSTRE=${LUSTRE:-$(dirname $0)/..}
RLUSTRE=${RLUSTRE:-$LUSTRE}
export MULTIOP=${MULTIOP:-multiop}

. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

# use small MDS + OST size to speed formatting time
# do not use too small MDSSIZE/OSTSIZE, which affect the default jouranl size
# STORED_MDSSIZE is used in test_18
STORED_MDSSIZE=$MDSSIZE
STORED_OSTSIZE=$OSTSIZE
MDSSIZE=200000
OSTSIZE=200000

if ! combined_mgs_mds; then
    # bug number for skipped test:    23954
    ALWAYS_EXCEPT="$ALWAYS_EXCEPT       24b"
fi

# pass "-E lazy_itable_init" to mke2fs to speed up the formatting time
if [[ "$LDISKFS_MKFS_OPTS" != *lazy_itable_init* ]]; then
	LDISKFS_MKFS_OPTS=$(csa_add "$LDISKFS_MKFS_OPTS" -E lazy_itable_init)
fi

[ $(facet_fstype $SINGLEMDS) = "zfs" ] &&
# bug number for skipped test:        LU-2778 LU-4444
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 57b     69"

init_logging

#
require_dsh_mds || exit 0
require_dsh_ost || exit 0
#
[ "$SLOW" = "no" ] && EXCEPT_SLOW="30a 31 45 69"

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
	echo "start mgs"
	start mgs $(mgsdevname) $MGS_MOUNT_OPTS
}

start_mdt() {
	local num=$1
	local facet=mds$num
	local dev=$(mdsdevname $num)
	shift 1

	echo "start mds service on `facet_active_host $facet`"
	start $facet ${dev} $MDS_MOUNT_OPTS $@ || return 94
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
}

stop_ost() {
	echo "stop ost1 service on `facet_active_host ost1`"
	# These tests all use non-failover stop
	stop ost1 -f || return 98
}

start_ost2() {
	echo "start ost2 service on `facet_active_host ost2`"
	start ost2 $(ostdevname 2) $OST_MOUNT_OPTS $@ || return 92
}

stop_ost2() {
	echo "stop ost2 service on `facet_active_host ost2`"
	# These tests all use non-failover stop
	stop ost2 -f || return 93
}

mount_client() {
	local MOUNTPATH=$1
	echo "mount $FSNAME on ${MOUNTPATH}....."
	zconf_mount $(hostname) $MOUNTPATH || return 96
}

remount_client() {
	local mountopt="remount,$1"
	local MOUNTPATH=$2
	echo "remount '$1' lustre on ${MOUNTPATH}....."
	zconf_mount $(hostname) $MOUNTPATH "$mountopt" || return 96
}

umount_client() {
	local MOUNTPATH=$1
	echo "umount lustre on ${MOUNTPATH}....."
	zconf_umount $(hostname) $MOUNTPATH || return 97
}

manual_umount_client(){
	local rc
	local FORCE=$1
	echo "manual umount lustre on ${MOUNT}...."
	do_facet client "umount -d ${FORCE} $MOUNT"
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
	umount_client $MOUNT || return 200
	cleanup_nocli || return $?
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

build_test_filter

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
	start_mdt 1 || error "MDT0 start fail"
	echo "start mds second time.."
	start_mdt 1 && error "2nd MDT start should fail"
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
	cleanup
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
	umount -d $MOUNT &
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
		error false "unexpected entry in mtab before mount" && return 10

	start_ost || error "OST start failed"
	start_mds || error "MDS start failed"
	stop_ost || error "Unable to stop OST1"
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	cleanup || error "cleanup_nocli failed with $?"
	grep " $MOUNT " /etc/mtab &&
		error "$MOUNT entry in mtab after unmount"
	pass
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
	if combined_mgs_mds ; then
		skip "combined mgs and mds"
		return 0
	fi

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

is_blkdev () {
	local facet=$1
	local dev=$2
	local size=${3:-""}

	local rc=0
	do_facet $facet "test -b $dev" || rc=1
	if [[ "$size" ]]; then
		local in=$(do_facet $facet "dd if=$dev of=/dev/null bs=1k \
			   count=1 skip=$size 2>&1" |
			awk '($3 == "in") { print $1 }')
		[[ $in  = "1+0" ]] || rc=1
	fi
	return $rc
}

#
# Test 16 was to "verify that lustre will correct the mode of OBJECTS".
# But with new MDS stack we don't care about the mode of local objects
# anymore, so this test is removed. See bug 22944 for more details.
#

test_17() {
	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
		return
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
	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
		return
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

	[ -z "$OK" ] && skip_env "$MDSDEV too small for ${MIN}kB MDS" && return

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
	stop_ost || error "Unable to stop OST1"
}
run_test 19b "start/stop OSTs without MDS"

test_20() {
	# first format the ost/mdt
	start_mds || error "MDS start failed"
	start_ost || error "Unable to start OST1"
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	check_mount || error "check_mount failed"
	rm -f $DIR/$tfile || error "remove $DIR/$tfile failed."
	remount_client ro $MOUNT || error "remount_client with ro failed"
	touch $DIR/$tfile && error "$DIR/$tfile created incorrectly"
	[ -e $DIR/$tfile ] && error "$DIR/$tfile exists incorrectly"
	remount_client rw $MOUNT || error "remount_client with rw failed"
	touch $DIR/$tfile || error "touch $DIR/$tfile failed"
	MCNT=$(grep -c $MOUNT /etc/mtab)
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
        if combined_mgs_mds ; then
                skip "need separate mgs device" && return 0
        fi
        stopall

        reformat

	start_mgs || error "unable to start MGS"
	start_ost || error "unable to start OST1"
	start_ost2 || error "unable to start OST2"
	start_mds || error "MDS start failed"
	wait_osc_import_state mds ost2 FULL

	stop_ost || error "Unable to stop OST1"
	stop_ost2 || error "Unable to stop OST2"
	stop_mds || error "Unable to stop MDS"
	stop_mgs
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
	start_mgs || error "unable to start MGS"
}
run_test 21d "start mgs then ost and then mds"

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
	umount_client $MOUNT
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
	wait_osc_import_state client ost FULL
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
	stop_mds || error "stopping MDSes failed"
	stop_ost || error "stopping OSSes failed"
}
run_test 23a "interrupt client during recovery mount delay"

umount_client $MOUNT
cleanup_nocli

test_23b() {    # was test_23
	start_mds || error "MDS start failed"
	start_ost || error "Unable to start OST1"
	# Simulate -EINTR during mount OBD_FAIL_LDLM_CLOSE_THREAD
	$LCTL set_param fail_loc=0x80000313
	mount_client $MOUNT
	cleanup || error "cleanup failed with rc $?"
}
run_test 23b "Simulate -EINTR during mount"

fs2mds_HOST=$mds_HOST
fs2ost_HOST=$ost_HOST

MDSDEV1_2=$fs2mds_DEV
OSTDEV1_2=$fs2ost_DEV
OSTDEV2_2=$fs3ost_DEV

cleanup_fs2() {
	trap 0
	echo "umount $MOUNT2 ..."
	umount $MOUNT2 || true
	echo "stopping fs2mds ..."
	stop fs2mds -f || true
	echo "stopping fs2ost ..."
	stop fs2ost -f || true
}

test_24a() {
	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})

	if [ -z "$fs2ost_DEV" -o -z "$fs2mds_DEV" ]; then
		is_blkdev $SINGLEMDS $MDSDEV &&
		skip_env "mixed loopback and real device not working" && return
	fi

	[ -n "$ost1_HOST" ] && fs2ost_HOST=$ost1_HOST

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2ostdev=$(ostdevname 1_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)
	local fs2ostvdev=$(ostvdevname 1_2)

	# test 8-char fsname as well
	local FSNAME2=test1234

	add fs2mds $(mkfs_opts mds1 ${fs2mdsdev} ) --nomgs --mgsnode=$MGSNID \
		--fsname=${FSNAME2} --reformat $fs2mdsdev $fs2mdsvdev || exit 10

	add fs2ost $(mkfs_opts ost1 ${fs2ostdev}) --fsname=${FSNAME2} \
		--reformat $fs2ostdev $fs2ostvdev || exit 10

	setup
	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS && trap cleanup_fs2 EXIT INT
	start fs2ost $fs2ostdev $OST_MOUNT_OPTS
	mkdir -p $MOUNT2 || error "mkdir $MOUNT2 failed"
	$MOUNT_CMD $MGSNID:/${FSNAME2} $MOUNT2 || error "$MOUNT_CMD failed"
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

	if [ -z "$fs2mds_DEV" ]; then
		local dev=${SINGLEMDS}_dev
		local MDSDEV=${!dev}
		is_blkdev $SINGLEMDS $MDSDEV &&
		skip_env "mixed loopback and real device not working" && return
	fi

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)

	add fs2mds $(mkfs_opts mds1 ${fs2mdsdev} ) --mgs --fsname=${FSNAME}2 \
		--reformat $fs2mdsdev $fs2mdsvdev || exit 10
	setup
	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS &&
		error "start MDS should fail"
	stop fs2mds -f
	cleanup || error "cleanup failed with rc $?"
}
run_test 24b "Multiple MGSs on a single node (should return err)"

test_25() {
	setup
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
	start_ost || error "Unable to start OST1"
	start_mds || error "Unable to start MDS"
	echo "Requeue thread should have started: "
	ps -e | grep ll_cfg_requeue
	set_conf_param_and_check ost1					      \
	   "$LCTL get_param -n obdfilter.$FSNAME-OST0000.client_cache_seconds" \
	   "$FSNAME-OST0000.ost.client_cache_seconds" ||
		error "set_conf_param_and_check ost1 failed"
	cleanup_nocli || error "cleanup_nocli failed with rc $?"
}
run_test 27a "Reacquire MGS lock if OST started first"

test_27b() {
	# FIXME. ~grev
	setup
	local device=$(do_facet $SINGLEMDS "$LCTL get_param -n devices" |
			awk '($3 ~ "mdt" && $4 ~ "MDT0000") { print $4 }')

	facet_failover $SINGLEMDS
	set_conf_param_and_check $SINGLEMDS				\
		"$LCTL get_param -n mdt.$device.identity_acquire_expire" \
		"$device.mdt.identity_acquire_expire" ||
		error "set_conf_param_and_check $SINGLEMDS failed"
	set_conf_param_and_check client				 \
		"$LCTL get_param -n mdc.$device-mdc-*.max_rpcs_in_flight"\
		"$device.mdc.max_rpcs_in_flight" ||
		error "set_conf_param_and_check client failed"
	check_mount
	cleanup || error "cleanup failed with $?"
}
run_test 27b "Reacquire MGS lock after failover"

test_28() {
	setup
	TEST="$LCTL get_param -n llite.$FSNAME-*.max_read_ahead_whole_mb"
	PARAM="$FSNAME.llite.max_read_ahead_whole_mb"
	ORIG=$($TEST)
	FINAL=$(($ORIG + 1))
	set_conf_param_and_check client "$TEST" "$PARAM" $FINAL ||
		error "first set_conf_param_and_check client failed"
	FINAL=$(($FINAL + 1))
	set_conf_param_and_check client "$TEST" "$PARAM" $FINAL ||
		error "second set_conf_param_and_check client failed"
	umount_client $MOUNT || error "umount_client $MOUNT failed"
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	RESULT=$($TEST)
	if [ $RESULT -ne $FINAL ]; then
		error "New config not seen: wanted $FINAL got $RESULT"
	else
		echo "New config success: got $RESULT"
	fi
	set_conf_param_and_check client "$TEST" "$PARAM" $ORIG ||
		error "third set_conf_param_and_check client failed"
	cleanup || error "cleanup failed with rc $?"
}
run_test 28 "permanent parameter setting"

test_28a() { # LU-4221
	[[ $(lustre_version_code ost1) -ge $(version_code 2.5.52) ]] ||
		{ skip "Need OST version at least 2.5.52" && return 0; }
	[ "$(facet_fstype ost1)" = "zfs" ] &&
		skip "LU-4221: no such proc params for ZFS OSTs" && return

	local name
	local param
	local cmd
	local old
	local new
	local device="$FSNAME-OST0000"

	setup

	# In this test we will set three kinds of proc parameters with
	# lctl conf_param:
	# 1. the ones moved from the OFD to the OSD, and only their
	#    symlinks kept in obdfilter
	# 2. non-symlink ones in the OFD
	# 3. non-symlink ones in the OSD

	# Check 1.
	# prepare a symlink parameter in the OFD
	name="writethrough_cache_enable"
	param="$device.ost.$name"
	cmd="$LCTL get_param -n obdfilter.$device.$name"

	# conf_param the symlink parameter in the OFD
	old=$(do_facet ost1 $cmd)
	new=$(((old + 1) % 2))
	set_conf_param_and_check ost1 "$cmd" "$param" $new ||
		error "lctl conf_param $device.ost.$param=$new failed"

	# conf_param the target parameter in the OSD
	param="$device.osd.$name"
	cmd="$LCTL get_param -n osd-*.$device.$name"
	set_conf_param_and_check ost1 "$cmd" "$param" $old ||
		error "lctl conf_param $device.osd.$param=$old failed"

	# Check 2.
	# prepare a non-symlink parameter in the OFD
	name="client_cache_seconds"
	param="$device.ost.$name"
	cmd="$LCTL get_param -n obdfilter.$device.$name"

	# conf_param the parameter in the OFD
	old=$(do_facet ost1 $cmd)
	new=$((old * 2))
	set_conf_param_and_check ost1 "$cmd" "$param" $new ||
		error "lctl conf_param $device.ost.$param=$new failed"
	set_conf_param_and_check ost1 "$cmd" "$param" $old ||
		error "lctl conf_param $device.ost.$param=$old failed"

	# Check 3.
	# prepare a non-symlink parameter in the OSD
	name="lma_self_repair"
	param="$device.osd.$name"
	cmd="$LCTL get_param -n osd-*.$device.$name"

	# conf_param the parameter in the OSD
	old=$(do_facet ost1 $cmd)
	new=$(((old + 1) % 2))
	set_conf_param_and_check ost1 "$cmd" "$param" $new ||
		error "lctl conf_param $device.osd.$param=$new failed"
	set_conf_param_and_check ost1 "$cmd" "$param" $old ||
		error "lctl conf_param $device.osd.$param=$old failed"

	cleanup || error "cleanup failed with $?"
}
run_test 28a "set symlink parameters permanently with conf_param"

test_29() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "$OSTCOUNT < 2, skipping" && return
        setup > /dev/null 2>&1
	start_ost2 || error "Unable to start OST2"
	sleep 10

	local PARAM="$FSNAME-OST0001.osc.active"
        local PROC_ACT="osc.$FSNAME-OST0001-osc-[^M]*.active"
        local PROC_UUID="osc.$FSNAME-OST0001-osc-[^M]*.ost_server_uuid"

        ACTV=$($LCTL get_param -n $PROC_ACT)
	DEAC=$((1 - $ACTV))
	set_conf_param_and_check client \
		"$LCTL get_param -n $PROC_ACT" "$PARAM" $DEAC ||
		error "set_conf_param_and_check client failed"
	# also check ost_server_uuid status
	RESULT=$($LCTL get_param -n $PROC_UUID | grep DEACTIV)
	if [ -z "$RESULT" ]; then
		error "Client not deactivated: $($LCTL get_param \
		       -n $PROC_UUID)"
	else
		echo "Live client success: got $RESULT"
	fi

	# check MDTs too
	for num in $(seq $MDSCOUNT); do
		local mdtosc=$(get_mdtosc_proc_path mds${num} $FSNAME-OST0001)
		local MPROC="osc.$mdtosc.active"
		local MAX=30
		local WAIT=0
		while [ 1 ]; do
			sleep 5
			RESULT=$(do_facet mds${num} "$LCTL get_param -n $MPROC")
			[ ${PIPESTATUS[0]} = 0 ] || error "Can't read $MPROC"
			if [ $RESULT -eq $DEAC ]; then
				echo -n "MDT deactivated also after"
				echo "$WAIT sec (got $RESULT)"
				break
			fi
			WAIT=$((WAIT + 5))
			if [ $WAIT -eq $MAX ]; then
				error "MDT active: wanted $DEAC got $RESULT"
			fi
			echo "Waiting $(($MAX - $WAIT))secs for MDT deactivated"
		done
	done
	# test new client starts deactivated
	umount_client $MOUNT || error "umount_client $MOUNT failed"
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	RESULT=$($LCTL get_param -n $PROC_UUID | grep DEACTIV | grep NEW)
	if [ -z "$RESULT" ]; then
		error "New client start active: $(lctl get_param -n $PROC_UUID)"
	else
		echo "New client success: got $RESULT"
	fi

	# make sure it reactivates
	set_conf_param_and_check client \
		"$LCTL get_param -n $PROC_ACT" "$PARAM" $ACTV ||
		error "lctl get_param $PROC_ACT $PARAM $ACTV failed"

	umount_client $MOUNT
	stop_ost2 || error "Unable to stop OST2"
	cleanup_nocli || error "cleanup_nocli failed with $?"
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 29 "permanently remove an OST"

test_30a() {
	setup

	echo Big config llog
	TEST="$LCTL get_param -n llite.$FSNAME-*.max_read_ahead_whole_mb"
	ORIG=$($TEST)
	LIST=(1 2 3 4 5 4 3 2 1 2 3 4 5 4 3 2 1 2 3 4 5)
	for i in ${LIST[@]}; do
		set_conf_param_and_check client "$TEST" \
			"$FSNAME.llite.max_read_ahead_whole_mb" $i ||
			error "Set $FSNAME.llite.max_read_ahead_whole_mb failed"
	done
	# make sure client restart still works
	umount_client $MOUNT
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	[ "$($TEST)" -ne "$i" ] &&
		error "Param didn't stick across restart $($TEST) != $i"
	pass

	echo Erase parameter setting
	do_facet mgs "$LCTL conf_param \
		      -d $FSNAME.llite.max_read_ahead_whole_mb" ||
		error "Erase param $FSNAME.llite.max_read_ahead_whole_mb failed"
	umount_client $MOUNT
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	FINAL=$($TEST)
	echo "deleted (default) value=$FINAL, orig=$ORIG"
	# assumes this parameter started at the default value
	[ "$FINAL" -eq "$ORIG" ] || fail "Deleted value=$FINAL, orig=$ORIG"

	cleanup || error "cleanup failed with rc $?"
}
run_test 30a "Big config llog and conf_param deletion"

test_30b() {
	setup

	# Make a fake nid.  Use the OST nid, and add 20 to the least significant
	# numerical part of it. Hopefully that's not already a failover address
	# for the server.
	OSTNID=$(do_facet ost1 "$LCTL get_param nis" | tail -1 | awk '{print $1}')
	ORIGVAL=$(echo $OSTNID | egrep -oi "[0-9]*@")
	NEWVAL=$((($(echo $ORIGVAL | egrep -oi "[0-9]*") + 20) % 256))
	NEW=$(echo $OSTNID | sed "s/$ORIGVAL/$NEWVAL@/")
	echo "Using fake nid $NEW"

	TEST="$LCTL get_param -n osc.$FSNAME-OST0000-osc-[^M]*.import |
		grep failover_nids | sed -n 's/.*\($NEW\).*/\1/p'"
	set_conf_param_and_check client "$TEST" \
		"$FSNAME-OST0000.failover.node" $NEW ||
		error "didn't add failover nid $NEW"
	NIDS=$($LCTL get_param -n osc.$FSNAME-OST0000-osc-[^M]*.import |
		grep failover_nids)
	echo $NIDS
	# The NIDS value is the failover nid strings and "[" and "]". So
	# we need to subtract the space taken by the delimiters. This has
	# changed from earlier version of Lustre but this test is run only
	# locally so this change will not break interop. See LU-3386
	NIDCOUNT=$(($(echo "$NIDS" | wc -w) - 3))
	echo "should have 2 failover nids: $NIDCOUNT"
	[ $NIDCOUNT -eq 2 ] || error "Failover nid not added"
	do_facet mgs "$LCTL conf_param -d $FSNAME-OST0000.failover.node" ||
		error "conf_param delete failed"
	umount_client $MOUNT
	mount_client $MOUNT || error "mount_client $MOUNT failed"

	NIDS=$($LCTL get_param -n osc.$FSNAME-OST0000-osc-[^M]*.import |
		grep failover_nids)
	echo $NIDS
	NIDCOUNT=$(($(echo "$NIDS" | wc -w) - 3))
	echo "only 1 final nid should remain: $NIDCOUNT"
	[ $NIDCOUNT -eq 1 ] || error "Failover nids not removed"

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
T32_BLIMIT=20480 # Kbytes
T32_ILIMIT=2

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

	if [ $FSNAME != t32fs -o $MDSCOUNT -ne 1 -o								\
		 \( -z "$MDSDEV" -a -z "$MDSDEV1" \) -o $OSTCOUNT -ne 1 -o			\
		 -z "$OSTDEV1" ]; then
		error "Needs FSNAME=t32fs MDSCOUNT=1 MDSDEV1=<nonexistent_file>"	\
			  "(or MDSDEV, in the case of b1_8) OSTCOUNT=1"					\
			  "OSTDEV1=<nonexistent_file>"
	fi

	mkdir $tmp || {
		echo "Found stale $tmp"
		return 1
	}

	mkdir $tmp/src || return 1
	tar cf - -C $src . | tar xf - -C $tmp/src
	dd if=/dev/zero of=$tmp/src/t32_qf_old bs=1M \
		count=$(($T32_BLIMIT / 1024 / 2))
	chown $T32_QID.$T32_QID $tmp/src/t32_qf_old

	# format ost with comma-separated NIDs to verify LU-4460
	local failnid="$(h2$NETTYPE 1.2.3.4),$(h2$NETTYPE 4.3.2.1)"
	MGSNID="$MGSNID,$MGSNID" OSTOPT="--failnode=$failnid" formatall

	setupall

	[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.3.50) ] &&
		$LFS quotacheck -ug /mnt/$FSNAME
	$LFS setquota -u $T32_QID -b 0 -B $T32_BLIMIT -i 0 -I $T32_ILIMIT \
		/mnt/$FSNAME

	tar cf - -C $tmp/src . | tar xf - -C /mnt/$FSNAME
	stopall

	mkdir $tmp/img || return 1

	setupall
	pushd /mnt/$FSNAME
	ls -Rni --time-style=+%s >$tmp/img/list
	find . ! -name .lustre -type f -exec sha1sum {} \; |
		sort -k 2 >$tmp/img/sha1sums
	popd
	$LCTL get_param -n version | head -n 1 |
		sed -e 's/^lustre: *//' >$tmp/img/commit

	[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.3.50) ] &&
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

	stopall

	pushd $tmp/src
	find -type f -exec sha1sum {} \; | sort -k 2 >$tmp/sha1sums.src
	popd

	if ! diff -u $tmp/sha1sums.src $tmp/img/sha1sums; then
		echo "Data verification failed"
	fi

	uname -r >$tmp/img/kernel
	uname -m >$tmp/img/arch

	mv ${MDSDEV1:-$MDSDEV} $tmp/img
	mv $OSTDEV1 $tmp/img

	version=$(sed -e 's/\(^[0-9]\+\.[0-9]\+\)\(.*$\)/\1/' $tmp/img/commit |
			  sed -e 's/\./_/g')	# E.g., "1.8.7" -> "1_8"
	dst=$(cd $dst; pwd)
	pushd $tmp/img
	tar cjvf $dst/disk$version-$(facet_fstype $SINGLEMDS).tar.bz2 -S *
	popd

	rm -r $tmp
}
#run_test 32newtarball "Create a new test_32 disk image tarball for this version"

#
# The list of applicable tarballs is returned via the caller's
# variable "tarballs".
#
t32_check() {
	local node=$(facet_active_host $SINGLEMDS)
	local r="do_node $node"

	if [ "$CLIENTONLY" ]; then
		skip "Client-only testing"
		exit 0
	fi

	if ! $r which $TUNEFS; then
		skip_env "tunefs.lustre required on $node"
		exit 0
	fi

	local IMGTYPE=$(facet_fstype $SINGLEMDS)

	tarballs=$($r find $RLUSTRE/tests -maxdepth 1 -name \'disk*-$IMGTYPE.tar.bz2\')

	if [ -z "$tarballs" ]; then
		skip "No applicable tarballs found"
		exit 0
	fi
}

t32_test_cleanup() {
	local tmp=$TMP/t32
	local fstype=$(facet_fstype $SINGLEMDS)
	local rc=$?

	if $shall_cleanup_lustre; then
		umount $tmp/mnt/lustre || rc=$?
	fi
	if $shall_cleanup_mdt; then
		$r umount -d $tmp/mnt/mdt || rc=$?
	fi
	if $shall_cleanup_mdt1; then
		$r umount -d $tmp/mnt/mdt1 || rc=$?
	fi
	if $shall_cleanup_ost; then
		$r umount -d $tmp/mnt/ost || rc=$?
	fi

	$r rm -rf $tmp
	rm -rf $tmp
	if [ $fstype == "zfs" ]; then
		$r $ZPOOL destroy t32fs-mdt1 || rc=$?
		$r $ZPOOL destroy t32fs-ost1 || rc=$?
	fi
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

	while ((i < 20)); do
		echo "Unloading modules on $node: Attempt $i"
		do_rpc_nodes $node $LUSTRE_RMMOD $(facet_fstype $SINGLEMDS) &&
			all_removed=true
		do_rpc_nodes $node check_mem_leak || return 1
		if $all_removed; then
			do_rpc_nodes $node load_modules
			return 0
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
	do_rpc_nodes $node "$LCTL devices_list"
	return 1
}

t32_verify_quota() {
	local node=$1
	local fsname=$2
	local mnt=$3
	local fstype=$(facet_fstype $SINGLEMDS)
	local qval
	local cmd

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
	[ $qval -eq $T32_BLIMIT ] || {
		echo "blimit, act:$qval, exp:$T32_BLIMIT"
		return 1
	}

	qval=$($LFS quota -v -u $T32_QID $mnt |
		awk 'BEGIN { num='7' } { if ($1 == "'$mnt'") \
		{ if (NF == 1) { getline } else { num++ } ; print $num;} }' \
		| tr -d "*")
	[ $qval -eq $T32_ILIMIT ] || {
		echo "ilimit, act:$qval, exp:$T32_ILIMIT"
		return 1
	}

	do_node $node $LCTL conf_param $fsname.quota.mdt=ug
	cmd="$LCTL get_param -n osd-$fstype.$fsname-MDT0000"
	cmd=$cmd.quota_slave.enabled
	wait_update $node "$cmd" "ug" || {
		echo "Enable mdt quota failed"
		return 1
	}

	do_node $node $LCTL conf_param $fsname.quota.ost=ug
	cmd="$LCTL get_param -n osd-$fstype.$fsname-OST0000"
	cmd=$cmd.quota_slave.enabled
	wait_update $node "$cmd" "ug" || {
		echo "Enable ost quota failed"
		return 1
	}

	chmod 0777 $mnt
	runas -u $T32_QID -g $T32_QID dd if=/dev/zero of=$mnt/t32_qf_new \
		bs=1M count=$(($T32_BLIMIT / 1024)) oflag=sync && {
		echo "Write succeed, but expect -EDQUOT"
		return 1
	}
	rm -f $mnt/t32_qf_new

	runas -u $T32_QID -g $T32_QID createmany -m $mnt/t32_qf_ \
		$T32_ILIMIT && {
		echo "Create succeed, but expect -EDQUOT"
		return 1
	}
	unlinkmany $mnt/t32_qf_ $T32_ILIMIT

	return 0
}

t32_test() {
	local tarball=$1
	local writeconf=$2
	local dne_upgrade=${dne_upgrade:-"no"}
	local ff_convert=${ff_convert:-"no"}
	local shall_cleanup_mdt=false
	local shall_cleanup_mdt1=false
	local shall_cleanup_ost=false
	local shall_cleanup_lustre=false
	local node=$(facet_active_host $SINGLEMDS)
	local r="do_node $node"
	local node2=$(facet_active_host mds2)
	local tmp=$TMP/t32
	local img_commit
	local img_kernel
	local img_arch
	local img_bspace
	local img_ispace
	local fsname=t32fs
	local nid=$($r $LCTL list_nids | head -1)
	local mopts
	local uuid
	local nrpcs_orig
	local nrpcs
	local list
	local fstype=$(facet_fstype $SINGLEMDS)
	local mdt_dev=$tmp/mdt
	local ost_dev=$tmp/ost

	trap 'trap - RETURN; t32_test_cleanup' RETURN

	mkdir -p $tmp/mnt/lustre || error "mkdir $tmp/mnt/lustre failed"
	$r mkdir -p $tmp/mnt/{mdt,ost}
	$r tar xjvf $tarball -S -C $tmp || {
		error_noexit "Unpacking the disk image tarball"
		return 1
	}
	img_commit=$($r cat $tmp/commit)
	img_kernel=$($r cat $tmp/kernel)
	img_arch=$($r cat $tmp/arch)
	img_bspace=$($r cat $tmp/bspace)
	img_ispace=$($r cat $tmp/ispace)
	echo "Upgrading from $(basename $tarball), created with:"
	echo "  Commit: $img_commit"
	echo "  Kernel: $img_kernel"
	echo "    Arch: $img_arch"
	echo "OST version: $(get_lustre_version ost1)"

	# The conversion can be made only when both of the following
	# conditions are satisfied:
	# - ost device img version < 2.3.64
	# - ost server version >= 2.5
	[ $(version_code $img_commit) -ge $(version_code 2.3.64) -o \
		$(lustre_version_code ost1) -lt $(version_code 2.5.0) ] &&
			ff_convert="no"

	if [ $fstype == "zfs" ]; then
		# import pool first
		$r $ZPOOL import -f -d $tmp t32fs-mdt1
		$r $ZPOOL import -f -d $tmp t32fs-ost1
		mdt_dev=t32fs-mdt1/mdt1
		ost_dev=t32fs-ost1/ost1
		wait_update_facet $SINGLEMDS "$ZPOOL list |
			awk '/^t32fs-mdt1/ { print \\\$1 }'" "t32fs-mdt1" || {
				error_noexit "import zfs pool failed"
				return 1
			}
	fi

	$r $LCTL set_param debug="$PTLDEBUG"

	$r $TUNEFS --dryrun $mdt_dev || {
		$r losetup -a
		error_noexit "tunefs.lustre before mounting the MDT"
		return 1
	}
	if [ "$writeconf" ]; then
		mopts=writeconf
		if [ $fstype == "ldiskfs" ]; then
			mopts="loop,$mopts"
			$r $TUNEFS --quota $mdt_dev || {
				$r losetup -a
				error_noexit "Enable mdt quota feature"
				return 1
			}
		fi
	else
		if [ -n "$($LCTL list_nids | grep -v '\(tcp\|lo\)[[:digit:]]*$')" ]; then
			[[ $(lustre_version_code mgs) -ge $(version_code 2.3.59) ]] ||
			{ skip "LU-2200: Cannot run over Inifiniband w/o lctl replace_nids "
				"(Need MGS version at least 2.3.59)"; return 0; }

			local osthost=$(facet_active_host ost1)
			local ostnid=$(do_node $osthost $LCTL list_nids | head -1)

			mopts=nosvc
			if [ $fstype == "ldiskfs" ]; then
				mopts="loop,$mopts"
			fi
			$r $MOUNT_CMD -o $mopts $mdt_dev $tmp/mnt/mdt
			$r $LCTL replace_nids $fsname-OST0000 $ostnid
			$r $LCTL replace_nids $fsname-MDT0000 $nid
			$r umount -d $tmp/mnt/mdt
		fi

		mopts=exclude=$fsname-OST0000
		if [ $fstype == "ldiskfs" ]; then
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

	if [ "$dne_upgrade" != "no" ]; then
		local fs2mdsdev=$(mdsdevname 1_2)
		local fs2mdsvdev=$(mdsvdevname 1_2)

		echo "mkfs new MDT on ${fs2mdsdev}...."
		if [ $(facet_fstype mds1) == ldiskfs ]; then
			mkfsoptions="--mkfsoptions=\\\"-J size=8\\\""
		fi

		add fs2mds $(mkfs_opts mds2 $fs2mdsdev $fsname) --reformat \
			   $mkfsoptions $fs2mdsdev $fs2mdsvdev > /dev/null || {
			error_noexit "Mkfs new MDT failed"
			return 1
		}

		$r $TUNEFS --dryrun $fs2mdsdev || {
			error_noexit "tunefs.lustre before mounting the MDT"
			return 1
		}

		echo "mount new MDT....$fs2mdsdev"
		$r mkdir -p $tmp/mnt/mdt1
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
		if [ $fstype == "ldiskfs" ]; then
			mopts="loop,$mopts"
			$r $TUNEFS --quota $ost_dev || {
				$r losetup -a
				error_noexit "Enable ost quota feature"
				return 1
			}
		fi
	else
		mopts=mgsnode=$nid
		if [ $fstype == "ldiskfs" ]; then
			mopts="loop,$mopts"
		fi
	fi
	$r $MOUNT_CMD -o $mopts $ost_dev $tmp/mnt/ost || {
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

	$r $LCTL conf_param $fsname-OST0000.osc.max_dirty_mb=15 || {
		error_noexit "Setting \"max_dirty_mb\""
		return 1
	}
	$r $LCTL conf_param $fsname-OST0000.failover.node=$nid || {
		error_noexit "Setting OST \"failover.node\""
		return 1
	}
	$r $LCTL conf_param $fsname-MDT0000.mdc.max_rpcs_in_flight=9 || {
		error_noexit "Setting \"max_rpcs_in_flight\""
		return 1
	}
	$r $LCTL conf_param $fsname-MDT0000.failover.node=$nid || {
		error_noexit "Setting MDT \"failover.node\""
		return 1
	}
	$r $LCTL pool_new $fsname.interop || {
		error_noexit "Setting \"interop\""
		return 1
	}
	$r $LCTL conf_param $fsname-MDT0000.lov.stripesize=4M || {
		error_noexit "Setting \"lov.stripesize\""
		return 1
	}

	if [ "$ff_convert" != "no" -a $(facet_fstype ost1) == "ldiskfs" ]; then
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
		$r $LCTL conf_param \
				$fsname-MDT0001.mdc.max_rpcs_in_flight=9 || {
			error_noexit "Setting MDT1 \"max_rpcs_in_flight\""
			return 1
		}
		$r $LCTL conf_param $fsname-MDT0001.failover.node=$nid || {
			error_noexit "Setting MDT1 \"failover.node\""
			return 1
		}
		$r $LCTL conf_param $fsname-MDT0001.lov.stripesize=4M || {
			error_noexit "Setting MDT1 \"lov.stripesize\""
			return 1
		}

	fi

	if [ "$writeconf" ]; then
		$MOUNT_CMD $nid:/$fsname $tmp/mnt/lustre || {
			error_noexit "Mounting the client"
			return 1
		}
		shall_cleanup_lustre=true
		$LCTL set_param debug="$PTLDEBUG"

		t32_verify_quota $node $fsname $tmp/mnt/lustre || {
			error_noexit "verify quota failed"
			return 1
		}

		if [ "$dne_upgrade" != "no" ]; then
			$LFS mkdir -i 1 $tmp/mnt/lustre/remote_dir || {
				error_noexit "set remote dir failed"
				return 1
			}

			pushd $tmp/mnt/lustre
			tar -cf - . --exclude=./remote_dir |
				tar -xvf - -C remote_dir 1>/dev/null || {
				error_noexit "cp to remote dir failed"
				return 1
			}
			popd
		fi

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
				pushd $tmp/mnt/lustre/remote_dir
			else
				pushd $tmp/mnt/lustre
			fi

			find ! -name .lustre -type f -exec sha1sum {} \; |
				sort -k 2 >$tmp/sha1sums || {
				error_noexit "sha1sum"
				return 1
			}
			popd
			if ! diff -ub $tmp/sha1sums.orig $tmp/sha1sums; then
				error_noexit "sha1sum verification failed"
				return 1
			fi
		else
			echo "sha1sum verification skipped"
		fi

		if [ "$dne_upgrade" != "no" ]; then
			rm -rf $tmp/mnt/lustre/remote_dir || {
				error_noexit "remove remote dir failed"
				return 1
			}
		fi

		if $r test -f $tmp/list; then
			#
			# There is not a Test Framework API to copy files to or
			# from a remote node.
			#
			# LU-2393 - do both sorts on same node to ensure locale
			# is identical
			$r cat $tmp/list | sort -k 6 >$tmp/list.orig
			pushd $tmp/mnt/lustre
			ls -Rni --time-style=+%s | sort -k 6 >$tmp/list || {
				error_noexit "ls"
				return 1
			}
			popd
			#
			# 32-bit and 64-bit clients use different algorithms to
			# convert FIDs into inode numbers.  Hence, remove the inode
			# numbers from the lists, if the original list was created
			# on an architecture with different number of bits per
			# "long".
			#
			if [ $(t32_bits_per_long $(uname -m)) != \
				$(t32_bits_per_long $img_arch) ]; then
				echo "Different number of bits per \"long\" from the disk image"
				for list in list.orig list; do
					sed -i -e 's/^[0-9]\+[ \t]\+//' $tmp/$list
				done
			fi
			if ! diff -ub $tmp/list.orig $tmp/list; then
				error_noexit "list verification failed"
				return 1
			fi
		else
			echo "list verification skipped"
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
		$r $LCTL conf_param $fsname-MDT0000.mdc.max_rpcs_in_flight=$nrpcs || {
			error_noexit "Changing \"max_rpcs_in_flight\""
			return 1
		}
		wait_update $HOSTNAME "$LCTL get_param \
			-n mdc.*MDT0000*.max_rpcs_in_flight" $nrpcs || {
			error_noexit "Verifying \"max_rpcs_in_flight\""
			return 1
		}

		umount $tmp/mnt/lustre || {
			error_noexit "Unmounting the client"
			return 1
		}
		shall_cleanup_lustre=false
	else
		if [ "$dne_upgrade" != "no" ]; then
			$r umount -d $tmp/mnt/mdt1 || {
				error_noexit "Unmounting the MDT2"
				return 1
			}
			shall_cleanup_mdt1=false
		fi

		$r umount -d $tmp/mnt/mdt || {
			error_noexit "Unmounting the MDT"
			return 1
		}
		shall_cleanup_mdt=false

		$r umount -d $tmp/mnt/ost || {
			error_noexit "Unmounting the OST"
			return 1
		}
		shall_cleanup_ost=false

		t32_reload_modules $node || {
			error_noexit "Reloading modules"
			return 1
		}

		# mount a second time to make sure we didnt leave upgrade flag on
		$r $TUNEFS --dryrun $mdt_dev || {
			$r losetup -a
			error_noexit "tunefs.lustre before remounting the MDT"
			return 1
		}

		mopts=exclude=$fsname-OST0000
		if [ $fstype == "ldiskfs" ]; then
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
		t32_test $tarball writeconf || let "rc += $?"
	done
	return $rc
}
run_test 32b "Upgrade with writeconf"

test_32c() {
	local tarballs
	local tarball
	local rc=0

	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	t32_check
	for tarball in $tarballs; do
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
		ff_convert=yes t32_test $tarball || rc=$?
	done
	return $rc
}
run_test 32d "convert ff test"

test_33a() { # bug 12333, was test_33
	local FSNAME2=test-123
	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})
	local mkfsoptions

	[ -n "$ost1_HOST" ] && fs2ost_HOST=$ost1_HOST

	if [ -z "$fs2ost_DEV" -o -z "$fs2mds_DEV" ]; then
		local dev=${SINGLEMDS}_dev
		local MDSDEV=${!dev}
		is_blkdev $SINGLEMDS $MDSDEV &&
			skip_env "mixed loopback and real device not working" &&
			return
	fi

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2ostdev=$(ostdevname 1_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)
	local fs2ostvdev=$(ostvdevname 1_2)

	if [ $(facet_fstype mds1) == ldiskfs ]; then
		mkfsoptions="--mkfsoptions=\\\"-J size=8\\\"" # See bug 17931.
	fi

	add fs2mds $(mkfs_opts mds1 ${fs2mdsdev}) --mgs --fsname=${FSNAME2} \
		--reformat $mkfsoptions $fs2mdsdev $fs2mdsvdev || exit 10
	add fs2ost $(mkfs_opts ost1 ${fs2ostdev}) --mgsnode=$MGSNID \
		--fsname=${FSNAME2} --index=8191 --reformat $fs2ostdev \
		$fs2ostvdev || exit 10

	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS && trap cleanup_fs2 EXIT INT
	start fs2ost $fs2ostdev $OST_MOUNT_OPTS
	do_facet $SINGLEMDS "$LCTL conf_param $FSNAME2.sys.timeout=200" ||
		error "$LCTL conf_param $FSNAME2.sys.timeout=200 failed"
	mkdir -p $MOUNT2 || error "mkdir $MOUNT2 failed"
	$MOUNT_CMD $MGSNID:/${FSNAME2} $MOUNT2 || error "$MOUNT_CMD failed"
	echo "ok."

	cp /etc/hosts $MOUNT2/ || error "copy /etc/hosts $MOUNT2/ failed"
	$GETSTRIPE $MOUNT2/hosts || error "$GETSTRIPE $MOUNT2/hosts failed"

	umount -d $MOUNT2
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
	do_facet mgs "$LCTL conf_param \
		      ${device}.failover.node=$(h2$NETTYPE $FAKENID)" ||
		error "Setting ${device}.failover.node=\
		       $(h2$NETTYPE $FAKENID) failed."

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
	remote_mds || { skip "local MDS" && return 0; }
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
	do_facet mgs "$LCTL conf_param \
		      ${device}.failover.node=$(h2$NETTYPE $FAKENID)" ||
		error "Set ${device}.failover.node=\
		       $(h2$NETTYPE $FAKENID) failed"

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
	[ $OSTCOUNT -lt 2 ] && skip_env "skipping test for single OST" && return

	[ "$ost_HOST" = "`hostname`" -o "$ost1_HOST" = "`hostname`" ] ||
		{ skip "remote OST" && return 0; }

	local rc=0
	local FSNAME2=test1234
	local fs3ost_HOST=$ost_HOST
	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})

	[ -n "$ost1_HOST" ] && fs2ost_HOST=$ost1_HOST && fs3ost_HOST=$ost1_HOST

	if [ -z "$fs2ost_DEV" -o -z "$fs2mds_DEV" -o -z "$fs3ost_DEV" ]; then
		is_blkdev $SINGLEMDS $MDSDEV &&
		skip_env "mixed loopback and real device not working" && return
	fi

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2ostdev=$(ostdevname 1_2)
	local fs3ostdev=$(ostdevname 2_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)
	local fs2ostvdev=$(ostvdevname 1_2)
	local fs3ostvdev=$(ostvdevname 2_2)

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

	umount -d $MOUNT2
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

	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Currently only applicable to ldiskfs-based MDTs"
		return
	fi

	echo "MDS :     $mdsdev"
	echo "SYMLINK : $mdsdev_sym"
	do_facet $SINGLEMDS rm -f $mdsdev_sym

	do_facet $SINGLEMDS ln -s $mdsdev $mdsdev_sym

	echo "mount symlink device - $mdsdev_sym"

	if ! do_facet $SINGLEMDS test -b $mdsdev; then
		opts=$(csa_add "$opts" -o loop)
	fi
	mount_op=$(do_facet $SINGLEMDS mount -v -t lustre $opts \
		$mdsdev_sym $mntpt 2>&1)
	rc=${PIPESTATUS[0]}

	echo mount_op=$mount_op

	do_facet $SINGLEMDS "umount -d $mntpt && rm -f $mdsdev_sym"

	if $(echo $mount_op | grep -q "unable to set tunable"); then
		error "set tunables failed for symlink device"
	fi

	[ $rc -eq 0 ] || error "mount symlink $mdsdev_sym failed! rc=$rc"
}
run_test 37 "verify set tunables works for symlink device"

test_38() { # bug 14222
	local fstype=$(facet_fstype $SINGLEMDS)
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
	if [ $(facet_fstype $SINGLEMDS) == ldiskfs ] &&
	   ! do_facet $SINGLEMDS test -b $(mdsdevname 1); then
		skip "Loop devices does not work with nosvc option"
		return
	fi

	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})

	start $SINGLEMDS $MDSDEV $MDS_MOUNT_OPTS -o nosvc -n
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS
	start $SINGLEMDS $MDSDEV $MDS_MOUNT_OPTS -o nomgs,force
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	sleep 5

	echo "blah blah" > $MOUNT/$tfile
	cat $MOUNT/$tfile

	umount_client $MOUNT || error "umount_client $MOUNT failed"
	stop ost1 -f || error "unable to stop OST1"
	stop_mds || error "Unable to stop MDS"
	stop_mds || error "Unable to stop MDS on second try"
	unload_modules_conf || error "unload_modules_conf failed"
}
run_test 41a "mount mds with --nosvc and --nomgs"

test_41b() {
	if [ $(facet_fstype $SINGLEMDS) == ldiskfs ] &&
	   ! do_facet $SINGLEMDS test -b $(mdsdevname 1); then
		skip "Loop devices does not work with nosvc option"
		return
	fi

	! combined_mgs_mds && skip "needs combined mgs device" && return 0

	stopall
	reformat
	local MDSDEV=$(mdsdevname ${SINGLEMDS//mds/})

	start $SINGLEMDS $MDSDEV $MDS_MOUNT_OPTS -o nosvc -n
	start_ost || error "Unable to start OST1"
	start $SINGLEMDS $MDSDEV $MDS_MOUNT_OPTS -o nomgs,force
	mount_client $MOUNT || error "mount_client $MOUNT failed"
	sleep 5

	echo "blah blah" > $MOUNT/$tfile
	cat $MOUNT/$tfile || error "cat $MOUNT/$tfile failed"

	umount_client $MOUNT || error "umount_client $MOUNT failed"
	stop_ost || error "Unable to stop OST1"
	stop_mds || error "Unable to stop MDS"
	stop_mds || error "Unable to stop MDS on second try"
}
run_test 41b "mount mds with --nosvc and --nomgs on first mount"

test_41c() {
	local server_version=$(lustre_version_code $SINGLEMDS)

	[[ $server_version -ge $(version_code 2.6.52) ]] ||
	[[ $server_version -ge $(version_code 2.5.26) &&
	   $server_version -lt $(version_code 2.5.50) ]] ||
	[[ $server_version -ge $(version_code 2.5.4) &&
	   $server_version -lt $(version_code 2.5.11) ]] ||
		{ skip "Need MDS version 2.5.4+ or 2.5.26+ or 2.6.52+"; return; }

	cleanup
	# MDT concurent start
	#define OBD_FAIL_TGT_DELAY_CONNECT 0x703
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x703"
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS &
	local pid=$!
	sleep 2
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x0"
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS &
	local pid2=$!
	wait $pid2
	local rc2=$?
	wait $pid
	local rc=$?
	if [ $rc == 0 ] && [ $rc2 == 114 ]; then
		echo "1st MDT start succeed"
		echo "2nd MDT start failed with EALREADY"
	elif [ $rc2 == 0 ] && [ $rc == 114 ]; then
		echo "1st MDT start failed with EALREADY"
		echo "2nd MDT start succeed"
	else
		stop mds1 -f
		error "unexpected concurent MDT mounts result, rc=$rc rc2=$rc2"
	fi

	# OST concurent start
	#define OBD_FAIL_TGT_DELAY_CONNECT 0x703
	do_facet ost1 "$LCTL set_param fail_loc=0x703"
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS &
	pid=$!
	sleep 2
	do_facet ost1 "$LCTL set_param fail_loc=0x0"
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS &
	pid2=$!
	wait $pid2
	rc2=$?
	wait $pid
	rc=$?
	if [ $rc == 0 ] && [ $rc2 == 114 ]; then
		echo "1st OST start succeed"
		echo "2nd OST start failed with EALREADY"
	elif [ $rc2 == 0 ] && [ $rc == 114 ]; then
		echo "1st OST start failed with EALREADY"
		echo "2nd OST start succeed"
	else
		stop mds1 -f
		stop ost1 -f
		error "unexpected concurent OST mounts result, rc=$rc rc2=$rc2"
	fi
	# cleanup
	stop mds1 -f
	stop ost1 -f

	# verify everything ok
	start_mds
	if [ $? != 0 ]
	then
		stop mds1 -f
		error "MDT(s) start failed"
	fi

	start_ost
	if [ $? != 0 ]
	then
		stop mds1 -f
		stop ost1 -f
		error "OST(s) start failed"
	fi

	mount_client $MOUNT
	if [ $? != 0 ]
	then
		stop mds1 -f
		stop ost1 -f
		error "client start failed"
	fi
	check_mount
	if [ $? != 0 ]
	then
		stop mds1 -f
		stop ost1 -f
		error "client mount failed"
	fi
	cleanup
}
run_test 41c "concurent mounts of MDT/OST should all fail but one"

test_42() { #bug 14693
	setup
	check_mount || error "client was not mounted"

	do_facet mgs $LCTL conf_param $FSNAME.llite.some_wrong_param=10
	umount_client $MOUNT ||
		error "unmounting client failed with invalid llite param"
	mount_client $MOUNT ||
		error "mounting client failed with invalid llite param"

	do_facet mgs $LCTL conf_param $FSNAME.sys.some_wrong_param=20
	cleanup || error "stopping $FSNAME failed with invalid sys param"
	load_modules
	setup
	check_mount || error "client was not mounted with invalid sys param"
	cleanup || error "stopping $FSNAME failed with invalid sys param"
}
run_test 42 "allow client/server mount/unmount with invalid config param"

test_43() {
	[[ $(lustre_version_code mgs) -ge $(version_code 2.5.58) ]] ||
		{ skip "Need MDS version at least 2.5.58" && return 0; }
	[ $UID -ne 0 -o $RUNAS_ID -eq 0 ] && skip_env "run as root"

	ID1=${ID1:-501}
	USER1=$(cat /etc/passwd | grep :$ID1:$ID1: | cut -d: -f1)
	[ -z "$USER1" ] && skip_env "missing user with uid=$ID1 gid=$ID1" &&
		return

	setup
	chmod ugo+x $DIR || error "chmod 0 failed"
	set_conf_param_and_check mds					\
		"$LCTL get_param -n mdt.$FSNAME-MDT0000.root_squash"	\
		"$FSNAME.mdt.root_squash"				\
		"0:0"
	wait_update $HOSTNAME						\
		"$LCTL get_param -n llite.${FSNAME}*.root_squash"	\
		"0:0" ||
		error "check llite root_squash failed!"
	set_conf_param_and_check mds					\
		"$LCTL get_param -n mdt.$FSNAME-MDT0000.nosquash_nids"	\
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

	mkdir $DIR/$tdir-rootdir || error "mkdir failed"
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
	set_conf_param_and_check mds					\
		"$LCTL get_param -n mdt.$FSNAME-MDT0000.root_squash"	\
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
	NIDLIST="2@elan $NIDLIST 192.168.0.[2,10]@tcp"
	NIDLIST=$(echo $NIDLIST | tr -s ' ' ' ')
	set_conf_param_and_check mds					\
		"$LCTL get_param -n mdt.$FSNAME-MDT0000.nosquash_nids"	\
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
}
run_test 43 "check root_squash and nosquash_nids"

umount_client $MOUNT
cleanup_nocli

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
	#define OBD_FAIL_PTLRPC_LONG_UNLINK   0x50f
	do_facet client "$LCTL set_param fail_loc=0x50f"
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
	    wait_osc_import_state client ost$i FULL
	done

	#second client see all ost's

	mount_client $MOUNT2 || error "mount_client failed"
	$SETSTRIPE -c -1 $MOUNT2 || error "$SETSTRIPE -c -1 $MOUNT2 failed"
	$GETSTRIPE $MOUNT2 || error "$GETSTRIPE $MOUNT2 failed"

	echo "ok" > $MOUNT2/widestripe
	$GETSTRIPE $MOUNT2/widestripe ||
		error "$GETSTRIPE $MOUNT2/widestripe failed"
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

	# reformat after this test is needed - if test will failed
	# we will have unkillable file at FS
	reformat_and_config
}

test_48() { # bug 17636
	reformat
	setup_noconfig
	check_mount || error "check_mount failed"

	$SETSTRIPE -c -1 $MOUNT || error "$SETSTRIPE -c -1 $MOUNT failed"
	$GETSTRIPE $MOUNT || error "$GETSTRIPE $MOUNT failed"

	echo "ok" > $MOUNT/widestripe
	$GETSTRIPE $MOUNT/widestripe ||
		error "$GETSTRIPE $MOUNT/widestripe failed"

	trap cleanup_48 EXIT ERR

	# fill acl buffer for avoid expand lsm to them
	getent passwd | awk -F : '{ print "u:"$1":rwx" }' |  while read acl; do
	    setfacl -m $acl $MOUNT/widestripe
	done

	stat $MOUNT/widestripe || error "stat $MOUNT/widestripe failed"

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
        # Test both statfs and lfs df and fail if either one fails
	multiop_bg_pause $1 f_
	RC1=$?
	PID=$!
	killall -USR1 multiop
	[ $RC1 -ne 0 ] && log "lazystatfs multiop failed"
	wait $PID || { RC1=$?; log "multiop return error "; }

	$LFS df &
	PID=$!
	sleep 5
	kill -s 0 $PID
	RC2=$?
	if [ $RC2 -eq 0 ]; then
	    kill -s 9 $PID
	    log "lazystatfs df failed"
	fi

	RC=0
	[[ $RC1 -ne 0 || $RC2 -eq 0 ]] && RC=1
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
        wait_osc_import_state mds ost DISCONN

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

	umount_client $MOUNT || error "Unable to unmount client"
	stop_ost || error "Unable to stop OST1"
	stop_mds || error "Unable to stop MDS"
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 50f "normal statfs one server in down"

test_50g() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "$OSTCOUNT < 2, skipping" && return
	setup
	start_ost2 || error "Unable to start OST2"
        wait_osc_import_state mds ost2 FULL
        wait_osc_import_state client ost2 FULL

	local PARAM="${FSNAME}-OST0001.osc.active"

	$SETSTRIPE -c -1 $DIR/$tfile || error "$SETSTRIPE failed"
	do_facet mgs $LCTL conf_param $PARAM=0 ||
		error "Unable to deactivate OST"

	umount_client $MOUNT || error "Unable to unmount client"
	mount_client $MOUNT || error "Unable to mount client"
	# This df should not cause a panic
	df -k $MOUNT

	do_facet mgs $LCTL conf_param $PARAM=1 || error "Unable to activate OST"
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
	[ "$OSTCOUNT" -lt "2" ] && skip_env "$OSTCOUNT < 2, skipping" && return

	[ $(facet_fstype ost1) == zfs ] && import_zpool ost1
	do_facet ost1 "$TUNEFS --param osc.active=0 `ostdevname 1`" ||
		error "tunefs OST1 failed"
	start_mds  || error "Unable to start MDT"
	start_ost  || error "Unable to start OST1"
	start_ost2 || error "Unable to start OST2"
	mount_client $MOUNT || error "client start failed"

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	# activatate OSC for OST1
	local TEST="$LCTL get_param -n osc.${FSNAME}-OST0000-osc-[!M]*.active"
	set_conf_param_and_check client					\
		"$TEST" "${FSNAME}-OST0000.osc.active" 1 ||
		error "Unable to activate OST1"

	mkdir $DIR/$tdir/2 || error "mkdir $DIR/$tdir/2 failed"
	$SETSTRIPE -c -1 -i 0 $DIR/$tdir/2 ||
		error "$SETSTRIPE $DIR/$tdir/2 failed"
	sleep 1 && echo "create a file after OST1 is activated"
	# create some file
	createmany -o $DIR/$tdir/2/$tfile-%d 1

	# check OSC import is working
	stat $DIR/$tdir/2/* >/dev/null 2>&1 ||
		error "some OSC imports are still not connected"

	# cleanup
	umount_client $MOUNT || error "Unable to umount client"
	stop_ost2 || error "Unable to stop OST2"
	cleanup_nocli || error "cleanup_nocli failed with $?"
}
run_test 50h "LU-642: activate deactivated OST"

test_51() {
	local LOCAL_TIMEOUT=20

	reformat
	setup_noconfig
	check_mount || error "check_mount failed"

	mkdir $MOUNT/$tdir || error "mkdir $MOUNT/$tdir failed"
	$SETSTRIPE -c -1 $MOUNT/$tdir ||
		error "$SETSTRIPE -c -1 $MOUNT/$tdir failed"
	#define OBD_FAIL_MDS_REINT_DELAY         0x142
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x142"
	touch $MOUNT/$tdir/$tfile &
	local pid=$!
	sleep 2
	start_ost2 || error "Unable to start OST1"
	wait $pid
	stop_ost2 || error "Unable to stop OST1"
	cleanup || error "cleanup failed with $?"
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
	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
		return
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

	$SETSTRIPE -c -1 -S 1M $DIR/$tdir || error "$SETSTRIPE failed"

	for (( i=0; i < nrfiles; i++ )); do
		multiop $DIR/$tdir/$tfile-$i Ow1048576w1048576w524288c ||
			error "multiop failed"
		echo -n .
	done
	echo

	# backup files
	echo backup files to $TMP/files
	local files=$(find $DIR/$tdir -type f -newer $TMP/modified_first)
	copy_files_xattrs $(hostname) $TMP/files $TMP/file_xattrs $files ||
		error "Unable to copy files"

	umount_client $MOUNT || error "Unable to umount client"
	stop_ost || error "Unable to stop ost1"

	echo mount ost1 as ldiskfs
	do_node $ost1node mkdir -p $ost1mnt || error "Unable to create $ost1mnt"
	if ! do_node $ost1node test -b $ost1_dev; then
		loop="-o loop"
	fi
	do_node $ost1node mount -t $(facet_fstype ost1) $loop $ost1_dev \
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

	# recover objects dry-run
	echo "ll_recover_lost_found_objs dry_run"
	do_node $ost1node "ll_recover_lost_found_objs -n -d $ost1mnt/O" ||
		error "ll_recover_lost_found_objs failed"

	# recover objects
	echo "ll_recover_lost_found_objs fix run"
	do_node $ost1node "ll_recover_lost_found_objs -d $ost1mnt/lost+found" ||
		 error "ll_recover_lost_found_objs failed"

	# compare restored objects against saved ones
	diff_files_xattrs $ost1node $ost1tmp/objects $ost1tmp/object_xattrs $objects
	[ $? -eq 0 ] || error "Unable to diff objects"

	do_node $ost1node "umount $ost1mnt" ||
		error "Unable to umount ost1 as ldiskfs"

	start_ost || error "Unable to start OST1"
	mount_client $MOUNT || error "Unable to mount client"

	# compare files
	diff_files_xattrs $(hostname) $TMP/files $TMP/file_xattrs $files ||
		error "Unable to diff files"

	rm -rf $TMP/files $TMP/file_xattrs ||
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
		skip_env "module parameter forced $facet thread count" &&
		tmin=3 && tmax=$((3 * tmax))

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

	load_modules
	setup
	check_mount || return 41

	# Restore previous setting of MODOPTS_*
	setmodopts $modname "$oldvalue"

	# Check that $opts took
	tmin=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_min")
	tmax=$(do_facet $facet "$LCTL get_param -n ${paramp}.threads_max")
	tstarted=$(do_facet $facet \
		   "$LCTL get_param -n ${paramp}.threads_started")
	lassert 28 "$msg" '(($tstarted >= $tmin && $tstarted <= $tmax ))' ||
		return $?
	cleanup

	load_modules
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
	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
		return
	fi

	do_rpc_nodes $(facet_host ost1) run_llverdev $(ostdevname 1) -p ||
		error "llverdev failed with rc=$?"
	reformat_and_config
}
run_test 54a "test llverdev and partial verify of device"

test_54b() {
	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
		return
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
	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
		return
	fi

	local mdsdev=$(mdsdevname 1)
	local mdsvdev=$(mdsvdevname 1)

	for i in 1023 2048
	do
		add mds1 $(mkfs_opts mds1 ${mdsdev}) --reformat $mdsdev \
			$mdsvdev || exit 10
		add ost1 $(mkfs_opts ost1 $(ostdevname 1)) --index=$i \
			--reformat $(ostdevname 1) $(ostvdevname 1)
		setup_noconfig
		stopall
		setup_noconfig
		sync

		echo checking size of lov_objid for ost index $i
		LOV_OBJID_SIZE=$(do_facet mds1 "$DEBUGFS -R 'stat lov_objid' $mdsdev 2>/dev/null" | grep ^User | awk '{print $6}')
		if [ "$LOV_OBJID_SIZE" != $(lov_objid_size $i) ]; then
			error "lov_objid size has to be $(lov_objid_size $i), not $LOV_OBJID_SIZE"
		else
			echo ok, lov_objid size is correct: $LOV_OBJID_SIZE
		fi
		stopall
	done

	reformat
}
run_test 55 "check lov_objid size"

test_56() {
	local mds_journal_size_orig=$MDSJOURNALSIZE
	local n

	MDSJOURNALSIZE=16

	for num in $(seq 1 $MDSCOUNT); do
		add mds${num} $(mkfs_opts mds${num} $(mdsdevname $num)) \
			--reformat $(mdsdevname $num) $(mdsvdevname $num)
	done
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
	wait_osc_import_state mds ost1 FULL
	wait_osc_import_state mds ost2 FULL
	$SETSTRIPE --stripe-count=-1 $DIR/$tfile ||
		error "Unable to setstripe $DIR/$tfile"
	n=$($LFS getstripe --stripe-count $DIR/$tfile)
	[ "$n" -eq 2 ] || error "Stripe count not two: $n"
	rm $DIR/$tfile
	stopall
	MDSJOURNALSIZE=$mds_journal_size_orig
	reformat
}
run_test 56 "check big OST indexes and out-of-index-order start"

test_57a() { # bug 22656
	do_rpc_nodes $(facet_active_host ost1) load_modules_local
	local NID=$(do_facet ost1 "$LCTL get_param nis" |
		    tail -1 | awk '{print $1}')
	writeconf_or_reformat
	[ $(facet_fstype ost1) == zfs ] && import_zpool ost1
	do_facet ost1 "$TUNEFS --failnode=$NID `ostdevname 1`" ||
		error "tunefs failed"
	start_mgsmds
	start_ost && error "OST registration from failnode should fail"
	reformat
}
run_test 57a "initial registration from failnode should fail (should return errs)"

test_57b() {
	do_rpc_nodes $(facet_active_host ost1) load_modules_local
	local NID=$(do_facet ost1 "$LCTL get_param nis" |
		    tail -1 | awk '{print $1}')
	writeconf_or_reformat
	[ $(facet_fstype ost1) == zfs ] && import_zpool ost1
	do_facet ost1 "$TUNEFS --servicenode=$NID `ostdevname 1`" ||
		error "tunefs failed"
	start_mgsmds
	start_ost || error "OST registration from servicenode should not fail"
	reformat
}
run_test 57b "initial registration from servicenode should not fail"

count_osts() {
        do_facet mgs $LCTL get_param mgs.MGS.live.$FSNAME | grep OST | wc -l
}

test_58() { # bug 22658
	setup_noconfig
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	createmany -o $DIR/$tdir/$tfile-%d 100
	# make sure that OSTs do not cancel llog cookies before we unmount the MDS
#define OBD_FAIL_OBD_LOG_CANCEL_NET      0x601
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x601"
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
	do_facet mds "$LCTL set_param fail_loc=0"
	reformat
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
	local num

	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
		return
	fi

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
	reformat
}
run_test 60 "check mkfs.lustre --mkfsoptions -E -O options setting"

test_61() { # LU-80
	local reformat=false

	[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.1.53) ] ||
		{ skip "Need MDS version at least 2.1.53"; return 0; }

	if [ $(facet_fstype $SINGLEMDS) == ldiskfs ] &&
	   ! large_xattr_enabled; then
		reformat=true
		LDISKFS_MKFS_OPTS+=" -O large_xattr"

		for num in $(seq $MDSCOUNT); do
			add mds${num} $(mkfs_opts mds$num $(mdsdevname $num)) \
			--reformat $(mdsdevname $num) $(mdsvdevname $num) ||
			error "add mds $num failed"
		done
	fi

	setup_noconfig || error "setting up the filesystem failed"
	client_up || error "starting client failed"

	local file=$DIR/$tfile
	touch $file || error "touch $file failed"

	local large_value="$(generate_string $(max_xattr_size))"
	local small_value="bar"

    local name="trusted.big"
    log "save large xattr $name on $file"
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

    rm -f $file
    stopall
	if $reformat; then
		LDISKFS_MKFS_OPTS=${LDISKFS_MKFS_OPTS% -O large_xattr}
		reformat
	fi
}
run_test 61 "large xattr"

test_62() {
	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
		return
	fi

	# MRP-118
	local mdsdev=$(mdsdevname 1)
	local ostdev=$(ostdevname 1)

	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.2.51) ]] ||
		{ skip "Need MDS version at least 2.2.51"; return 0; }

	echo "disable journal for mds"
	do_facet mds tune2fs -O ^has_journal $mdsdev || error "tune2fs failed"
	start_mds && error "MDT start should fail"
	echo "disable journal for ost"
	do_facet ost1 tune2fs -O ^has_journal $ostdev || error "tune2fs failed"
	start_ost && error "OST start should fail"
	cleanup || error "cleanup failed with rc $?"
	reformat_and_config
}
run_test 62 "start with disabled journal"

test_63() {
	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
		return
	fi

	local inode_slab=$(do_facet $SINGLEMDS \
		"awk '/ldiskfs_inode_cache/ { print \\\$5 }' /proc/slabinfo")
	if [ -z "$inode_slab" ]; then
		skip "ldiskfs module has not been loaded"
		return
	fi

	echo "$inode_slab ldisk inodes per page"
	[ "$inode_slab" -ge "3" ] ||
		error "ldisk inode size is too big, $inode_slab objs per page"
	return
}
run_test 63 "Verify each page can at least hold 3 ldisk inodes"

test_64() {
	start_mds || error "unable to start MDS"
	start_ost || error "Unable to start OST1"
	start_ost2 || error "Unable to start second ost"
	mount_client $MOUNT || error "Unable to mount client"
	stop_ost2 || error "Unable to stop second ost"
	echo "$LFS df"
	$LFS df --lazy || error "lfs df failed"
	cleanup || error "cleanup failed with $?"
	#writeconf to remove all ost2 traces for subsequent tests
	writeconf_or_reformat
}
run_test 64 "check lfs df --lazy "

test_65() { # LU-2237
	# Currently, the test is only valid for ldiskfs backend
	[ "$(facet_fstype $SINGLEMDS)" != "ldiskfs" ] &&
		skip "non-ldiskfs backend" && return

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
		"mount -t $(facet_fstype $SINGLEMDS) $opts $devname $brpt"
	do_facet $SINGLEMDS "rm -f ${brpt}/last_rcvd"
	do_facet $SINGLEMDS "umount -d $brpt"

	# restart MDS, the "last_rcvd" file should be recreated.
	start_mds || error "fail to restart the MDS"
	stop_mds || error "Unable to stop MDS"
	obj=$(do_facet $SINGLEMDS \
	      "$DEBUGFS -c -R \\\"stat last_rcvd\\\" $devname" | grep Inode)
	[ -n "$obj" ] || error "fail to re-create the last_rcvd"
}
run_test 65 "re-create the lost last_rcvd file when server mount"

test_66() {
	[[ $(lustre_version_code mgs) -ge $(version_code 2.3.59) ]] ||
		{ skip "Need MGS version at least 2.3.59"; return 0; }

	setup
	local OST1_NID=$(do_facet ost1 $LCTL list_nids | head -1)
	local MDS_NID=$(do_facet $SINGLEMDS $LCTL list_nids | head -1)

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

	echo "replace OST nid"
	do_facet mgs $LCTL replace_nids $FSNAME-OST0000 $OST1_NID ||
		error "replace nids failed"

	echo "command should accept two parameters"
	do_facet mgs $LCTL replace_nids $FSNAME-MDT0000 &&
		error "command should accept two params"

	echo "wrong nids list should not destroy the system"
	do_facet mgs $LCTL replace_nids $FSNAME-MDT0000 "wrong nids list" &&
		error "wrong parse"

	echo "replace MDS nid"
	do_facet mgs $LCTL replace_nids $FSNAME-MDT0000 $MDS_NID ||
		error "replace nids failed"

	if ! combined_mgs_mds ; then
		stop_mgs
	else
		stop_mds || error "Unable to stop MDS"
	fi

	setup_noconfig
	check_mount || error "error after nid replace"
	cleanup || error "cleanup failed"
	reformat
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

	lustre_routes_conversion $legacy $new > /dev/null
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

	[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.4.53) ] ||
		{ skip "Need MDS version at least 2.4.53"; return 0; }

	umount_client $MOUNT || error "umount client failed"

	start_mdt 1 || error "MDT start failed"
	start_ost || error "Unable to start OST1"

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

test_69() {
	local server_version=$(lustre_version_code $SINGLEMDS)

	[[ $server_version -lt $(version_code 2.4.2) ]] &&
		skip "Need MDS version at least 2.4.2" && return

	[[ $server_version -ge $(version_code 2.4.50) ]] &&
	[[ $server_version -lt $(version_code 2.5.0) ]] &&
		skip "Need MDS version at least 2.5.0" && return

	setup

	# use OST0000 since it probably has the most creations
	local OSTNAME=$(ostname_from_index 0)
	local mdtosc_proc1=$(get_mdtosc_proc_path mds1 $OSTNAME)
	local last_id=$(do_facet mds1 $LCTL get_param -n \
			osc.$mdtosc_proc1.prealloc_last_id)

	# Want to have OST LAST_ID over 1.5 * OST_MAX_PRECREATE to
	# verify that the LAST_ID recovery is working properly.  If
	# not, then the OST will refuse to allow the MDS connect
	# because the LAST_ID value is too different from the MDS
	#define OST_MAX_PRECREATE=20000
	local num_create=$((20000 * 5))

	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	$SETSTRIPE -i 0 $DIR/$tdir || error "$SETSTRIPE -i 0 $DIR/$tdir failed"
	createmany -o $DIR/$tdir/$tfile- $num_create ||
		error "createmany: failed to create $num_create files: $?"
	# delete all of the files with objects on OST0 so the
	# filesystem is not inconsistent later on
	$LFS find $MOUNT --ost 0 | xargs rm

	stop_ost || error "OST0 stop failure"
	add ost1 $(mkfs_opts ost1 $(ostdevname 1)) --reformat --replace \
		$(ostdevname 1) $(ostvdevname 1) ||
		error "reformat and replace $ostdev failed"
	start_ost || error "OST0 restart failure"
	wait_osc_import_state mds ost FULL

	touch $DIR/$tdir/$tfile-last || error "create file after reformat"
	local idx=$($GETSTRIPE -i $DIR/$tdir/$tfile-last)
	[ $idx -ne 0 ] && error "$DIR/$tdir/$tfile-last on $idx not 0" || true

	cleanup || error "cleanup failed with $?"
}
run_test 69 "replace an OST with the same index"

test_70a() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	local MDTIDX=1

	cleanup || error "cleanup failed with $?"

	start_mdt 1 || error "MDT0 start fail"

	start_ost || error "OST0 start fail"

	start_mdt 2 || error "MDT1 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "create $DIR/$tdir failed"

	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir fail"

	rm -rf $DIR/$tdir || error "delete dir fail"
	cleanup || error "cleanup failed with $?"
}
run_test 70a "start MDT0, then OST, then MDT1"

test_70b() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	local MDTIDX=1

	start_ost || error "OST0 start fail"

	start_mdt 1 || error "MDT0 start fail"
	start_mdt 2 || error "MDT1 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "create $DIR/$tdir failed"

	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir fail"

	rm -rf $DIR/$tdir || error "delete dir fail"

	cleanup || error "cleanup failed with $?"
}
run_test 70b "start OST, MDT1, MDT0"

test_70c() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	local MDTIDX=1

	start_mdt 1 || error "MDT0 start fail"
	start_mdt 2 || error "MDT1 start fail"
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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	local MDTIDX=1

	start_mdt 1 || error "MDT0 start fail"
	start_mdt 2 || error "MDT1 start fail"
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

test_71a() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	if combined_mgs_mds; then
		skip "needs separate MGS/MDT" && return
	fi
	local MDTIDX=1

	start_mdt 1 || error "MDT0 start fail"
	start_ost || error "OST0 start fail"
	start_mdt 2 || error "MDT1 start fail"
	start_ost2 || error "OST1 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "mkdir fail"
	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir succeed"

	mcreate $DIR/$tdir/remote_dir/$tfile || error "create file failed"
	rm -rf $DIR/$tdir || error "delete dir fail"

	umount_client $MOUNT || error "umount_client failed"
	stop_mdt 1 || error "MDT0 stop fail"
	stop_mdt 2 || error "MDT1 stop fail"
	stop_ost || error "OST0 stop fail"
	stop_ost2 || error "OST1 stop fail"
}
run_test 71a "start MDT0 OST0, MDT1, OST1"

test_71b() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	if combined_mgs_mds; then
		skip "needs separate MGS/MDT" && return
	fi
	local MDTIDX=1

	start_mdt 2 || error "MDT1 start fail"
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
	stop_mdt 1 || error "MDT0 stop fail"
	stop_mdt 2 || error "MDT1 stop fail"
	stop_ost || error "OST0 stop fail"
	stop_ost2 || error "OST1 stop fail"
}
run_test 71b "start MDT1, OST0, MDT0, OST1"

test_71c() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	if combined_mgs_mds; then
		skip "needs separate MGS/MDT" && return
	fi
	local MDTIDX=1

	start_ost || error "OST0 start fail"
	start_ost2 || error "OST1 start fail"
	start_mdt 2 || error "MDT1 start fail"
	start_mdt 1 || error "MDT0 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "mkdir fail"
	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir succeed"

	mcreate $DIR/$tdir/remote_dir/$tfile || error "create file failed"
	rm -rf $DIR/$tdir || error "delete dir fail"

	umount_client $MOUNT || error "umount_client failed"
	stop_mdt 1 || error "MDT0 stop fail"
	stop_mdt 2 || error "MDT1 stop fail"
	stop_ost || error "OST0 stop fail"
	stop_ost2 || error "OST1 stop fail"

}
run_test 71c "start OST0, OST1, MDT1, MDT0"

test_71d() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	if combined_mgs_mds; then
		skip "needs separate MGS/MDT" && return
	fi
	local MDTIDX=1

	start_ost || error "OST0 start fail"
	start_mdt 2 || error "MDT0 start fail"
	start_mdt 1 || error "MDT0 start fail"
	start_ost2 || error "OST1 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "mkdir fail"
	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
			error "create remote dir succeed"

	mcreate $DIR/$tdir/remote_dir/$tfile || error "create file failed"
	rm -rf $DIR/$tdir || error "delete dir fail"

	umount_client $MOUNT || error "umount_client failed"
	stop_mdt 1 || error "MDT0 stop fail"
	stop_mdt 2 || error "MDT1 stop fail"
	stop_ost || error "OST0 stop fail"
	stop_ost2 || error "OST1 stop fail"

}
run_test 71d "start OST0, MDT1, MDT0, OST1"

test_71e() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	if combined_mgs_mds; then
		skip "needs separate MGS/MDT" && return
	fi
	local MDTIDX=1

	start_ost || error "OST0 start fail"
	start_mdt 2 || error "MDT1 start fail"
	start_ost2 || error "OST1 start fail"
	start_mdt 1 || error "MDT0 start fail"

	mount_client $MOUNT || error "mount client fails"

	mkdir $DIR/$tdir || error "mkdir fail"
	$LFS mkdir -i $MDTIDX $DIR/$tdir/remote_dir ||
		error "create remote dir succeed"

	mcreate $DIR/$tdir/remote_dir/$tfile || error "create file failed"
	rm -rf $DIR/$tdir || error "delete dir fail"

	umount_client $MOUNT || error "umount_client failed"
	stop_mdt 1 || error "MDT0 stop fail"
	stop_mdt 2 || error "MDT1 stop fail"
	stop_ost || error "OST0 stop fail"
	stop_ost2 || error "OST1 stop fail"

}
run_test 71e "start OST0, MDT1, OST1, MDT0"

test_72() { #LU-2634
	local mdsdev=$(mdsdevname 1)
	local ostdev=$(ostdevname 1)
	local cmd="$E2FSCK -fnvd $mdsdev"
	local fn=3

	[ "$(facet_fstype $SINGLEMDS)" != "ldiskfs" ] &&
		skip "ldiskfs only test" && return

	#tune MDT with "-O extents"

	for num in $(seq $MDSCOUNT); do
		add mds${num} $(mkfs_opts mds$num $(mdsdevname $num)) \
		--reformat $(mdsdevname $num) $(mdsvdevname $num) ||
		error "add mds $num failed"
		$TUNE2FS -O extents $(mdsdevname $num)
	done

	add ost1 $(mkfs_opts ost1 $ostdev) --reformat $ostdev ||
		error "add $ostdev failed"
	start_mgsmds || error "start mds failed"
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
	load_modules
	[ $(facet_fstype ost1) == zfs ] && import_zpool ost1
	do_facet ost1 "$TUNEFS --failnode=1.2.3.4@$NETTYPE $(ostdevname 1)" ||
		error "1st tunefs failed"
	start_mgsmds || error "start mds failed"
	start_ost || error "start ost failed"
	mount_client $MOUNT || error "mount client failed"
	$LCTL get_param -n osc.*OST0000-osc-[^M]*.import | grep failover_nids |
		grep 1.2.3.4@$NETTYPE || error "failover nids haven't changed"
	umount_client $MOUNT || error "umount client failed"
	stopall
	reformat
}
run_test 73 "failnode to update from mountdata properly"

test_75() { # LU-2374
	[[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.4.1) ]] &&
	                skip "Need MDS version at least 2.4.1" && return

	local index=0
	local opts_mds="$(mkfs_opts mds1 $(mdsdevname 1)) \
		--reformat $(mdsdevname 1) $(mdsvdevname 1)"
	local opts_ost="$(mkfs_opts ost1 $(ostdevname 1)) \
		--reformat $(ostdevname 1) $(ostvdevname 1)"

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
	return 0
}
run_test 75 "The order of --index should be irrelevant"

test_76a() {
	[[ $(lustre_version_code mgs) -ge $(version_code 2.4.52) ]] ||
		{ skip "Need MDS version at least 2.4.52" && return 0; }
	setup
	local MDMB_PARAM="osc.*.max_dirty_mb"
	echo "Change MGS params"
	local MAX_DIRTY_MB=$($LCTL get_param -n $MDMB_PARAM |
		head -1)
	echo "max_dirty_mb: $MAX_DIRTY_MB"
	local NEW_MAX_DIRTY_MB=$((MAX_DIRTY_MB + MAX_DIRTY_MB))
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
run_test 76a "set permanent params set_param -P"

test_76b() { # LU-4783
	[[ $(lustre_version_code mgs) -ge $(version_code 2.5.57) ]] ||
		{ skip "Need MGS version at least 2.5.57" && return 0; }
	stopall
	setupall
	do_facet mgs $LCTL get_param mgs.MGS.live.params ||
		error "start params log failed"
	stopall
}
run_test 76b "verify params log setup correctly"

test_77() { # LU-3445
	local server_version=$(lustre_version_code $SINGLEMDS)

	[[ $server_version -ge $(version_code 2.2.60) ]] &&
	[[ $server_version -le $(version_code 2.4.0) ]] &&
		skip "Need MDS version < 2.2.60 or > 2.4.0" && return

	if [[ -z "$fs2ost_DEV" || -z "$fs2mds_DEV" ]]; then
		is_blkdev $SINGLEMDS $(mdsdevname ${SINGLEMDS//mds/}) &&
		skip_env "mixed loopback and real device not working" && return
	fi

	local fs2mdsdev=$(mdsdevname 1_2)
	local fs2ostdev=$(ostdevname 1_2)
	local fs2mdsvdev=$(mdsvdevname 1_2)
	local fs2ostvdev=$(ostvdevname 1_2)
	local fsname=test1234
	local mgsnid
	local failnid="$(h2$NETTYPE 1.2.3.4),$(h2$NETTYPE 4.3.2.1)"

	add fs2mds $(mkfs_opts mds1 $fs2mdsdev) --mgs --fsname=$fsname \
		--reformat $fs2mdsdev $fs2mdsvdev || error "add fs2mds failed"
	start fs2mds $fs2mdsdev $MDS_MOUNT_OPTS && trap cleanup_fs2 EXIT INT ||
		error "start fs2mds failed"

	mgsnid=$(do_facet fs2mds $LCTL list_nids | xargs | tr ' ' ,)
	[[ $mgsnid = *,* ]] || mgsnid+=",$mgsnid"

	add fs2ost $(mkfs_opts ost1 $fs2ostdev) --mgsnode=$mgsnid \
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
	[[ $(facet_fstype $SINGLEMDS) != ldiskfs ||
	   $(facet_fstype ost1) != ldiskfs ]] &&
		skip "only applicable to ldiskfs-based MDTs and OSTs" && return

	# reformat the Lustre filesystem with a smaller size
	local saved_MDSSIZE=$MDSSIZE
	local saved_OSTSIZE=$OSTSIZE
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
	for i in $(seq $num_files); do
		file=$MOUNT/$tdir/$tfile-$i
		dd if=/dev/urandom of=$file count=1 bs=1M ||
			error "(4) create $file failed"
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
		reformat || error "(10) reformat Lustre filesystem failed"
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
	reformat || error "(14) reformat Lustre filesystem failed"
}
run_test 78 "run resize2fs on MDT and OST filesystems"

test_79() { # LU-4227
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.5.59) ]] ||
		{ skip "Need MDS version at least 2.5.59"; return 0; }

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
	[ -n $mgsnode_opt ] &&
		opts_mds2=$(echo $opts_mds2 | sed -e "s/$mgsnode_opt//")

	mgsnode_opt=$(echo $opts_ost1 |
		awk '{ for ( i = 1; i < NF; i++ )
			if ( $i ~ "--mgsnode" ) { print $i; break } }')
	[ -n $mgsnode_opt ] &&
		opts_ost1=$(echo $opts_ost1 | sed -e "s/$mgsnode_opt//")

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

	reformat
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
	stopall
}
run_test 80 "mgc import reconnect race"

# Save the original values of $OSTCOUNT and $OSTINDEX$i.
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

	formatall
}

# The main purpose of this test is to ensure the OST_INDEX_LIST functions as
# expected. This test uses OST_INDEX_LIST to format OSTs with a randomly
# assigned index and ensures we can mount such a formatted file system
test_81() { # LU-4665
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.6.54) ]] ||
		{ skip "Need MDS version at least 2.6.54" && return; }
	[[ $OSTCOUNT -ge 3 ]] || { skip_env "Need at least 3 OSTs" && return; }

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
	[[ $max_easize -eq 128 ]] ||
		error "max_easize is $max_easize, should be 128 bytes"

	restore_ostindex
}
run_test 81 "sparse OST indexing"

# Wait OSTs to be active on both client and MDT side.
wait_osts_up() {
	local cmd="$LCTL get_param -n lov.$FSNAME-clilov-*.target_obd |
		awk 'BEGIN {c = 0} /ACTIVE/{c += 1} END {printf \\\"%d\\\", c}'"
	wait_update $HOSTNAME "eval $cmd" $OSTCOUNT ||
		error "wait_update OSTs up on client failed"

	cmd="$LCTL get_param -n lod.$FSNAME-MDT*-*.target_obd | sort -u |
	     awk 'BEGIN {c = 0} /ACTIVE/{c += 1} END {printf \\\"%d\\\", c}'"
	wait_update_facet $SINGLEMDS "eval $cmd" $OSTCOUNT ||
		error "wait_update OSTs up on MDT failed"
}

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
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.6.54) ]] ||
		{ skip "Need MDS version at least 2.6.54" && return; }
	[[ $OSTCOUNT -ge 3 ]] || { skip_env "Need at least 3 OSTs" && return; }

	stopall

	save_ostindex 3

	# Format OSTs with random sparse indices.
	local i
	local index
	local ost_indices
	for i in $(seq $OSTCOUNT); do
		index=$((RANDOM * 2))
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

	$LFS df $MOUNT || error "$LFS df $MOUNT failed"
	mkdir $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	# 1. If the file does not exist, new file will be created
	#    with specified OSTs.
	local file=$DIR/$tdir/$tfile-1
	local cmd="$SETSTRIPE -o $ost_indices $file"
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
	cmd="$SETSTRIPE -o $ost_indices $file"
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
	cmd="$SETSTRIPE -o $ost_indices -i $start_ost_idx $file"
	echo -e "\n$cmd"
	eval $cmd || error "$cmd failed"
	check_stripe_count $file $OSTCOUNT
	check_obdidx $file $ost_indices
	check_start_ost_idx $file $start_ost_idx

	file=$DIR/$tdir/$tfile-4
	cmd="$SETSTRIPE"
	cmd+=" -o $(exclude_items_from_list $ost_indices $start_ost_idx)"
	cmd+=" -i $start_ost_idx $file"
	echo -e "\n$cmd"
	eval $cmd && error "index $start_ost_idx should be in $ost_indices"

	# 5. Specifying OST indices for directory should fail with ENOSUPP.
	local dir=$DIR/$tdir/$tdir
	mkdir $dir || error "mkdir $dir failed"
	cmd="$SETSTRIPE -o $ost_indices $dir"
	echo -e "\n$cmd"
	eval $cmd && error "$cmd should fail, specifying OST indices" \
			   "for directory is not supported"

	restore_ostindex
}
run_test 82a "specify OSTs for file (succeed) or directory (fail)"

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
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.6.54) ]] ||
		{ skip "Need MDS version at least 2.6.54" && return; }
	[[ $OSTCOUNT -ge 4 ]] || { skip_env "Need at least 4 OSTs" && return; }

	stopall

	save_ostindex 4

	# Format OSTs with random sparse indices.
	local i
	local index
	local ost_indices
	for i in $(seq $OSTCOUNT); do
		index=$((RANDOM * 2))
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
	$LFS df $MOUNT || error "$LFS df $MOUNT failed"
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
	pool_list $ost_pool || error "list OST pool $ost_pool failed"

	# If [--pool|-p <pool_name>] is set with [--ost-list|-o <ost_indices>],
	# then the OSTs must be the members of the pool.
	local file=$DIR/$tdir/$tfile
	cmd="$SETSTRIPE -p $ost_pool -o $ost_idx_in_list $file"
	echo -e "\n$cmd"
	eval $cmd && error "OST with index $ost_idx_in_list should be" \
			   "in OST pool $ost_pool"

	# Only select OST $ost_idx_in_list from $ost_pool for file.
	ost_idx_in_list=${ost_idx_in_pool#*,}
	cmd="$SETSTRIPE -p $ost_pool -o $ost_idx_in_list $file"
	echo -e "\n$cmd"
	eval $cmd || error "$cmd failed"
	cmd="$GETSTRIPE $file"
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
	local dev
	local ostmnt
	local fstype
	local mnt_opts

	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		skip "Only applicable to ldiskfs-based MDTs"
		return
	fi

	dev=$(ostdevname 1)
	ostmnt=$(facet_mntpt ost1)
	fstype=$(facet_fstype ost1)

	# Mount the OST as an ldiskfs filesystem.
	log "mount the OST $dev as a $fstype filesystem"
	add ost1 $(mkfs_opts ost1 $dev) $FSTYPE_OPT \
		--reformat $dev $dev > /dev/null ||
		error "format ost1 error"

	if ! test -b $dev; then
		mnt_opts=$(csa_add "$OST_MOUNT_OPTS" -o loop)
	fi
	echo "mnt_opts $mnt_opts"
	do_facet ost1 mount -t $fstype $dev \
		$ostmnt $mnt_opts
	# Run llverfs on the mounted ldiskfs filesystem.
	# It is needed to get ENOSPACE.
	log "run llverfs in partial mode on the OST $fstype $ostmnt"
	do_rpc_nodes $(facet_host ost1) run_llverfs $ostmnt -vpl \
		"no" || error "run_llverfs error on $fstype"

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
	reformat
}
run_test 83 "ENOSPACE on OST doesn't cause message VFS: \
Busy inodes after unmount ..."

recovery_time_min() {
	local CONNECTION_SWITCH_MIN=5
	local CONNECTION_SWITCH_INC=5
	local CONNECTION_SWITCH_MAX
	local RECONNECT_DELAY_MAX
	local INITIAL_CONNECT_TIMEOUT
	local max
	local TO_20

	#CONNECTION_SWITCH_MAX=min(50, max($CONNECTION_SWITCH_MIN,$TIMEOUT)
	(($CONNECTION_SWITCH_MIN>$TIMEOUT)) && \
		max=$CONNECTION_SWITCH_MIN || max=$TIMEOUT
	(($max<50)) && CONNECTION_SWITCH_MAX=$max || CONNECTION_SWITCH_MAX=50

	#INITIAL_CONNECT_TIMEOUT = max(CONNECTION_SWITCH_MIN, \
	#obd_timeout/20)
	TO_20=$(($TIMEOUT/20))
	(($CONNECTION_SWITCH_MIN>$TO_20)) && \
		INITIAL_CONNECT_TIMEOUT=$CONNECTION_SWITCH_MIN || \
		INITIAL_CONNECT_TIMEOUT=$TO_20

	RECONNECT_DELAY_MAX=$(($CONNECTION_SWITCH_MAX+$CONNECTION_SWITCH_INC+ \
				$INITIAL_CONNECT_TIMEOUT))
	echo $((2*$RECONNECT_DELAY_MAX))
}

test_84() {
	local facet=$SINGLEMDS
	local num=$(echo $facet | tr -d "mds")
	local dev=$(mdsdevname $num)
	local time_min=$(recovery_time_min)
	local recovery_duration
	local completed_clients

	echo "start mds service on `facet_active_host $facet`"
	start $facet ${dev} $MDS_MOUNT_OPTS \
		"-o recovery_time_hard=$time_min,recovery_time_soft=$time_min"\
		$@ || return 94

	start_ost
	start_ost2

	echo "recovery_time_hard $time_min, recovery_time_soft $time_min, \
		timeout $TIMEOUT"

	mount_client $MOUNT1 || error "mount failed"
	mount_client $MOUNT2 || error "mount failed"

	replay_barrier $SINGLEMDS
	createmany -o $DIR1/$tfile-%d 1000

	# We need to catch the end of recovery window to extend it.
	# Skip 5 requests and add delay to request handling.
	#define OBD_FAIL_TGT_REPLAY_DELAY  0x709 | FAIL_SKIP
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x20000709"
	do_facet $SINGLEMDS "lctl set_param fail_val=5"

	facet_failover $SINGLEMDS || error "failover: $?"
	client_up

	echo "recovery status"
	do_facet $SINGLEMDS "$LCTL get_param -n \
				mdt.$FSNAME-MDT0000.recovery_status"

	recovery_duration=$(do_facet $SINGLEMDS "$LCTL get_param -n \
				mdt.$FSNAME-MDT0000.recovery_status" | \
				grep recovery_duration |awk '{print $2}')
	(($recovery_duration>$time_min)) && \
		error "recovery_duration > recovery_time_hard"
	completed_clients=$(do_facet $SINGLEMDS "$LCTL get_param -n \
				mdt.$FSNAME-MDT0000.recovery_status" | \
				grep completed_clients |awk '{print $2}')
	[ "$completed_clients" = "1/2" ] || \
		error "completed_clients != 1/2: "$completed_clients

	do_facet $SINGLEMDS "lctl set_param fail_loc=0"
	umount_client $MOUNT1
	umount_client $MOUNT2

	stop_ost
	stop_ost2
	stop_mds
}
run_test 84 "check recovery_hard_time"

if ! combined_mgs_mds ; then
	stop mgs
fi

cleanup_gss

# restore the values of MDSSIZE and OSTSIZE
MDSSIZE=$STORED_MDSSIZE
OSTSIZE=$STORED_OSTSIZE
reformat

complete $SECONDS
exit_status
