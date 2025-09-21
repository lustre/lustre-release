#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -e

ONLY=${ONLY:-"$*"}
PTLDEBUG=${PTLDEBUG:--1}
LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh


STORED_MDSSIZE=$MDSSIZE
STORED_OSTSIZE=$OSTSIZE
# use small MDS + OST size to speed formatting time
# do not use too small MDSSIZE/OSTSIZE, which affect the default journal size

mds1_FSTYPE=${mds1_FSTYPE:-$(facet_fstype mds1)}
ost1_FSTYPE=${ost1_FSTYPE:-$(facet_fstype ost1)}

MDSSIZE=200000
[ "$mds1_FSTYPE" = zfs ] && MDSSIZE=400000
OSTSIZE=200000
[ "$ost1_FSTYPE" = zfs ] && OSTSIZE=400000

# pass "-E lazy_itable_init" to mke2fs to speed up the formatting time
if [[ "$LDISKFS_MKFS_OPTS" != *lazy_itable_init* ]]; then
	LDISKFS_MKFS_OPTS=$(csa_add "$LDISKFS_MKFS_OPTS" -E lazy_itable_init)
fi

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
	writeconf_all $MDSCOUNT 2 || {
		echo "tunefs.lustre failed, reformatting instead"
		reformat_and_config
	}
	return 0
}

reformat() {
	formatall
}

start_mgs () {
	echo "start mgs service on $(facet_active_host mgs)"
	start mgs $(mgsdevname) $MGS_MOUNT_OPTS "$@"
}

start_mdt() {
	local num=$1
	local facet=mds$num
	local dev=$(mdsdevname $num)
	shift 1

	echo "start mds service on $(facet_active_host $facet)"
	start $facet ${dev} $MDS_MOUNT_OPTS "$@" || return 94
}

stop_mdt_no_force() {
	local num=$1
	local facet=mds$num
	local dev=$(mdsdevname $num)
	shift 1

	echo "stop mds service on $(facet_active_host $facet)"
	stop $facet || return 97
}

stop_mdt() {
	local num=$1
	local facet=mds$num
	local dev=$(mdsdevname $num)
	shift 1

	echo "stop mds service on $(facet_active_host $facet)"
	# These tests all use non-failover stop
	stop $facet -f || return 97
}

start_mds() {
	local mdscount=$MDSCOUNT
	local num

	[[ "$1" == "--mdscount" ]] && mdscount=$2 && shift 2

	for ((num=1; num <= mdscount; num++)); do
		start_mdt $num "$@" || return 94
	done
	for ((num=1; num <= mdscount; num++)); do
		wait_clients_import_state ${CLIENTS:-$HOSTNAME} mds${num} FULL
	done
}

start_mgsmds() {
	if ! combined_mgs_mds ; then
		start_mgs
	fi
	start_mds "$@"
}

stop_mds() {
	local num

	for ((num=1; num <= MDSCOUNT; num++)); do
		stop_mdt $num || return 97
	done
}

stop_mgs() {
	echo "stop mgs service on $(facet_active_host mgs)"
	# These tests all use non-failover stop
	stop mgs -f  || return 97
}

start_ost() {
	echo "start ost1 service on $(facet_active_host ost1)"
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS "$@" || return 95
	wait_clients_import_ready ${CLIENTS:-$HOSTNAME} ost1
}

stop_ost() {
	echo "stop ost1 service on $(facet_active_host ost1)"
	# These tests all use non-failover stop
	stop ost1 -f || return 98
}

start_ost2() {
	echo "start ost2 service on $(facet_active_host ost2)"
	start ost2 $(ostdevname 2) $OST_MOUNT_OPTS "$@" || return 92
	wait_clients_import_ready ${CLIENTS:-$HOSTNAME} ost2
}

stop_ost2() {
	echo "stop ost2 service on $(facet_active_host ost2)"
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
	zconf_umount $HOSTNAME $mountpath "$@" || return 97
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

	[[ -z "$1" ]] || force="-f"
	umount_client $MOUNT $force || return 200
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

name_chars=({a..z} {A..Z} {0..9})
generate_name() {
	local name=""

	for ((i = 0; i < $1; i++)); do
		name+=${name_chars[$((RANDOM % ${#name_chars[*]}))]};
	done

	echo "$name"
}
