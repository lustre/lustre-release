#!/bin/bash
#set -vx
set -e

ONLY=${ONLY:-"$*"}

# bug number for skipped test:
ALWAYS_EXCEPT="$POSIX_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] &&
	echo "Skipping tests: $ALWAYS_EXCEPT $EXCEPT"

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

POSIX_DIR=${POSIX_DIR:-"$LUSTRE/tests/posix"}
POSIX_SRC=${POSIX_SRC:-"/usr/src/posix"}
BASELINE_FS=${BASELINE_FS:-"ext4"}

# SLES does not support read-write access to an ext4 file system by default
[[ -e /etc/SuSE-release ]] && BASELINE_FS=ext3

if [[ $(facet_fstype $SINGLEMDS) = zfs ]]; then
	BASELINE_FS=zfs
	! which $ZFS $ZPOOL >/dev/null 2>&1 &&
		skip_env "need $ZFS and $ZPOOL commands" && exit 0

	POSIX_ZPOOL=$FSNAME-posix
	POSIX_ZFS=$POSIX_ZPOOL/${POSIX_ZPOOL##$FSNAME-}
fi

check_and_setup_lustre
build_test_filter

cleanup_loop_dev() {
    local mnt=$1
    local dev=$2
    local file=$3

    # if we only have 1 arg, we will search for dev
    if [[ $# = 1 ]]; then
        dev=$(losetup -a | grep "$mnt" | cut -d: -f1)
        [[ -n $dev ]] && losetup -d $dev
    else # we need all args
        [[ -z $mnt ]] || [[ -z $dev ]] || [[ -z $file ]] &&
            error "Can't cleanup loop device"
        umount -f $mnt
        losetup -d $dev && rm -rf $mnt
        rm -f $file
    fi

	[[ $BASELINE_FS != zfs ]] || destroy_zpool client $POSIX_ZPOOL
}

setup_loop_dev() {
	local mnt=$1
	local dev=$2
	local file=$3
	local rc=0

	echo "Make a loop file system with $file on $dev"
	dd if=/dev/zero of=$file bs=1024k count=500 > /dev/null
	if ! losetup $dev $file; then
		rc=$?
		echo "can't set up $dev for $file"
		return $rc
	fi

	if [[ $BASELINE_FS = zfs ]]; then
		create_zpool client $POSIX_ZPOOL $dev || return ${PIPESTATUS[0]}
		create_zfs client $POSIX_ZFS || return ${PIPESTATUS[0]}
		dev=$POSIX_ZFS

	elif ! eval mkfs.$BASELINE_FS $dev; then
		rc=$?
		echo "mkfs.$BASELINE_FS on $dev failed"
		return $rc
	fi
	mkdir -p $mnt
	if ! mount -t $BASELINE_FS $dev $mnt; then
		rc=$?
		echo "mount $BASELINE_FS failed"
		return $rc
	fi
	echo
	return $rc
}

test_1() {
	local allnodes="$(comma_list $(nodes_list))"
	local tfile="$TMP/$BASELINE_FS-file"
	local mntpnt=$POSIX_SRC/$BASELINE_FS
	local loopbase
	local loopdev
	local rc=0

	# We start at loop1 because posix build uses loop0
	[ -b /dev/loop/1 ] && loopbase=/dev/loop/
	[ -b /dev/loop1 ] && loopbase=/dev/loop
	if [ -z "$loopbase" ]; then
		# there is no /dev/loop by default on EL7, LU-6707.
		load_module loop max_loop=8 || error "load loop module failed"
		loopbase=/dev/loop
	fi

	for i in $(seq 1 7); do
		losetup $loopbase$i > /dev/null 2>&1 && continue || true
		loopdev=$loopbase$i
		break
	done

	[ -z "$loopdev" ] && error "Can not find loop device"

	if ! setup_loop_dev $mntpnt $loopdev $tfile; then
		cleanup_loop_dev "$mntpnt" "$loopdev" "$tfile"
		error "Setup loop device failed"
	fi

	# copy the source over to ext mount point
	if ! cp -af ${POSIX_SRC}/*.* $mntpnt; then
		cleanup_loop_dev "$mntpnt" "$loopdev" "$tfile"
		error "Copy POSIX test suite failed"
	fi
	export POSIX_SRC=$mntpnt
	. $POSIX_DIR/posix.cfg

	setup_posix_users $allnodes
	if ! setup_posix; then
		delete_posix_users $allnodes
		cleanup_loop_dev "$POSIX_SRC"
		cleanup_loop_dev "$mntpnt" "$loopdev" "$tfile"
		error "Setup POSIX test suite failed"
	fi

	log "Run POSIX test against lustre filesystem"
	run_posix $MOUNT $MGSNID $FSNAME compare ||
		error_noexit "Run POSIX testsuite on $MOUNT failed"

	[[ -d "$MOUNT/TESTROOT" ]] && rm -fr $MOUNT/TESTROOT
	delete_posix_users $allnodes
	cleanup_loop_dev "$POSIX_SRC"
	cleanup_loop_dev "$mntpnt" "$loopdev" "$tfile"
}
run_test 1 "install, build, run posix on $BASELINE_FS and lustre, then compare"

complete $SECONDS
check_and_cleanup_lustre
exit_status
