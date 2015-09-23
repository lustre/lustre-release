#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}

#Bug number for excepting test
ALWAYS_EXCEPT="$SANITY_LFSCK_EXCEPT"

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

require_dsh_mds || exit 0

load_modules

if ! check_versions; then
	skip "It is NOT necessary to test lfsck under interoperation mode"
	exit 0
fi

[[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.3.60) ]] &&
	skip "Need MDS version at least 2.3.60" && exit 0

LTIME=${LTIME:-120}

SAVED_MDSSIZE=${MDSSIZE}
SAVED_OSTSIZE=${OSTSIZE}
SAVED_OSTCOUNT=${OSTCOUNT}
# use small MDS + OST size to speed formatting time
# do not use too small MDSSIZE/OSTSIZE, which affect the default journal size
MDSSIZE=100000
OSTSIZE=100000
# no need too many OSTs, to reduce the format/start/stop overhead
[ $OSTCOUNT -gt 4 ] && OSTCOUNT=4

# build up a clean test environment.
formatall
setupall

[[ $(lustre_version_code $SINGLEMDS) -le $(version_code 2.4.90) ]] &&
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 2c"

[[ $(lustre_version_code ost1) -lt $(version_code 2.5.55) ]] &&
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 11 12 13 14 15 16 17 18 19 20 21"

[[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.6.50) ]] &&
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 2d 2e 3 22 23 24 25 26 27 28 29 30 31"

# DNE does not support striped directory on zfs-based backend yet.
[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 31"

build_test_filter

MDT_DEV="${FSNAME}-MDT0000"
OST_DEV="${FSNAME}-OST0000"
MDT_DEVNAME=$(mdsdevname ${SINGLEMDS//mds/})
START_NAMESPACE="do_facet $SINGLEMDS \
		$LCTL lfsck_start -M ${MDT_DEV} -t namespace"
START_LAYOUT="do_facet $SINGLEMDS \
		$LCTL lfsck_start -M ${MDT_DEV} -t layout"
START_LAYOUT_ON_OST="do_facet ost1 $LCTL lfsck_start -M ${OST_DEV} -t layout"
STOP_LFSCK="do_facet $SINGLEMDS $LCTL lfsck_stop -M ${MDT_DEV}"
SHOW_NAMESPACE="do_facet $SINGLEMDS \
		$LCTL get_param -n mdd.${MDT_DEV}.lfsck_namespace"
SHOW_LAYOUT="do_facet $SINGLEMDS \
		$LCTL get_param -n mdd.${MDT_DEV}.lfsck_layout"
SHOW_LAYOUT_ON_OST="do_facet ost1 \
		$LCTL get_param -n obdfilter.${OST_DEV}.lfsck_layout"
MOUNT_OPTS_SCRUB="-o user_xattr"
MOUNT_OPTS_NOSCRUB="-o user_xattr,noscrub"
MOUNT_OPTS_SKIP_LFSCK="-o user_xattr,skip_lfsck"

lfsck_prep() {
	local ndirs=$1
	local nfiles=$2
	local igif=$3

	check_mount_and_prep

	echo "preparing... $nfiles * $ndirs files will be created $(date)."
	if [ ! -z $igif ]; then
		#define OBD_FAIL_FID_IGIF	0x1504
		do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1504
	fi

	cp $LUSTRE/tests/*.sh $DIR/$tdir/
	if [ $ndirs -gt 0 ]; then
		createmany -d $DIR/$tdir/d $ndirs
		createmany -m $DIR/$tdir/f $ndirs
		if [ $nfiles -gt 0 ]; then
			for ((i = 0; i < $ndirs; i++)); do
				createmany -m $DIR/$tdir/d${i}/f $nfiles > \
					/dev/null || error "createmany $nfiles"
			done
		fi
		createmany -d $DIR/$tdir/e $ndirs
	fi

	if [ ! -z $igif ]; then
		touch $DIR/$tdir/dummy
		do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	fi

	echo "prepared $(date)."
}

run_e2fsck_on_mdt0() {
	[ $(facet_fstype $SINGLEMDS) != ldiskfs ] && return

	stop $SINGLEMDS > /dev/null || error "(0) Fail to the stop MDT0"
	run_e2fsck $(facet_active_host $SINGLEMDS) $(mdsdevname 1) "-n" |
		grep "Fix? no" && {
		run_e2fsck $(facet_active_host $SINGLEMDS) $(mdsdevname 1) "-n"
		error "(2) Detected inconsistency on MDT0"
	}
	start $SINGLEMDS $MDT_DEVNAME $MOUNT_OPTS_NOSCRUB > /dev/null ||
		error "(3) Fail to start MDT0"
}

test_0() {
	lfsck_prep 3 3

	#define OBD_FAIL_LFSCK_DELAY1		0x1600
	do_facet $SINGLEMDS $LCTL set_param fail_val=3 fail_loc=0x1600
	$START_NAMESPACE -r || error "(2) Fail to start LFSCK for namespace!"

	$SHOW_NAMESPACE || error "Fail to monitor LFSCK (3)"

	local STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(4) Expect 'scanning-phase1', but got '$STATUS'"

	$STOP_LFSCK || error "(5) Fail to stop LFSCK!"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "stopped" ] ||
		error "(6) Expect 'stopped', but got '$STATUS'"

	$START_NAMESPACE || error "(7) Fail to start LFSCK for namespace!"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(8) Expect 'scanning-phase1', but got '$STATUS'"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(9) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^updated_phase1/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(10) Expect nothing to be repaired, but got: $repaired"

	local scanned1=$($SHOW_NAMESPACE | awk '/^success_count/ { print $2 }')
	$START_NAMESPACE -r || error "(11) Fail to reset LFSCK!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(12) unexpected status"
	}

	local scanned2=$($SHOW_NAMESPACE | awk '/^success_count/ { print $2 }')
	[ $((scanned1 + 1)) -eq $scanned2 ] ||
		error "(13) Expect success $((scanned1 + 1)), but got $scanned2"

	echo "stopall, should NOT crash LU-3649"
	stopall || error "(14) Fail to stopall"
}
run_test 0 "Control LFSCK manually"

test_1a() {
	[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
		skip "OI Scrub not implemented for ZFS" && return

	lfsck_prep 1 1

	#define OBD_FAIL_FID_INDIR	0x1501
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1501
	touch $DIR/$tdir/dummy

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	umount_client $MOUNT
	$START_NAMESPACE -r || error "(3) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^dirent_repaired/ { print $2 }')
	# for interop with old server
	[ -z "$repaired" ] &&
		repaired=$($SHOW_NAMESPACE |
			 awk '/^updated_phase1/ { print $2 }')

	[ $repaired -eq 1 ] ||
		error "(5) Fail to repair crashed FID-in-dirent: $repaired"

	run_e2fsck_on_mdt0

	mount_client $MOUNT || error "(6) Fail to start client!"

	#define OBD_FAIL_FID_LOOKUP	0x1505
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1505
	ls $DIR/$tdir/ > /dev/null || error "(7) no FID-in-dirent."

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
}
run_test 1a "LFSCK can find out and repair crashed FID-in-dirent"

test_1b()
{
	[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
		skip "OI Scrub not implemented for ZFS" && return

	lfsck_prep 1 1

	#define OBD_FAIL_FID_INLMA	0x1502
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1502
	touch $DIR/$tdir/dummy

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	umount_client $MOUNT
	#define OBD_FAIL_FID_NOLMA	0x1506
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1506
	$START_NAMESPACE -r || error "(3) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^dirent_repaired/ { print $2 }')
	# for interop with old server
	[ -z "$repaired" ] &&
		repaired=$($SHOW_NAMESPACE |
			 awk '/^updated_phase1/ { print $2 }')

	[ $repaired -eq 1 ] ||
		error "(5) Fail to repair the missing FID-in-LMA: $repaired"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	run_e2fsck_on_mdt0

	mount_client $MOUNT || error "(6) Fail to start client!"

	#define OBD_FAIL_FID_LOOKUP	0x1505
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1505
	stat $DIR/$tdir/dummy > /dev/null || error "(7) no FID-in-LMA."

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
}
run_test 1b "LFSCK can find out and repair the missing FID-in-LMA"

test_2a() {
	lfsck_prep 1 1

	#define OBD_FAIL_LFSCK_LINKEA_CRASH	0x1603
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1603
	touch $DIR/$tdir/dummy

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	umount_client $MOUNT
	$START_NAMESPACE -r || error "(3) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^linkea_repaired/ { print $2 }')
	# for interop with old server
	[ -z "$repaired" ] &&
		repaired=$($SHOW_NAMESPACE |
			 awk '/^updated_phase2/ { print $2 }')

	[ $repaired -eq 1 ] ||
		error "(5) Fail to repair crashed linkEA: $repaired"

	run_e2fsck_on_mdt0

	mount_client $MOUNT || error "(6) Fail to start client!"

	stat $DIR/$tdir/dummy | grep "Links: 1" > /dev/null ||
		error "(7) Fail to stat $DIR/$tdir/dummy"

	local dummyfid=$($LFS path2fid $DIR/$tdir/dummy)
	local dummyname=$($LFS fid2path $DIR $dummyfid)
	[ "$dummyname" == "$DIR/$tdir/dummy" ] ||
		error "(8) Fail to repair linkEA: $dummyfid $dummyname"
}
run_test 2a "LFSCK can find out and repair crashed linkEA entry"

test_2b()
{
	lfsck_prep 1 1

	#define OBD_FAIL_LFSCK_LINKEA_MORE	0x1604
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1604
	touch $DIR/$tdir/dummy

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	umount_client $MOUNT
	$START_NAMESPACE -r || error "(3) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^updated_phase2/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(5) Fail to repair crashed linkEA: $repaired"

	run_e2fsck_on_mdt0

	mount_client $MOUNT || error "(6) Fail to start client!"

	stat $DIR/$tdir/dummy | grep "Links: 1" > /dev/null ||
		error "(7) Fail to stat $DIR/$tdir/dummy"

	local dummyfid=$($LFS path2fid $DIR/$tdir/dummy)
	local dummyname=$($LFS fid2path $DIR $dummyfid)
	[ "$dummyname" == "$DIR/$tdir/dummy" ] ||
		error "(8) Fail to repair linkEA: $dummyfid $dummyname"
}
run_test 2b "LFSCK can find out and remove invalid linkEA entry"

test_2c()
{
	lfsck_prep 1 1

	#define OBD_FAIL_LFSCK_LINKEA_MORE2	0x1605
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1605
	touch $DIR/$tdir/dummy

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	umount_client $MOUNT
	$START_NAMESPACE -r || error "(3) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^updated_phase2/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(5) Fail to repair crashed linkEA: $repaired"

	run_e2fsck_on_mdt0

	mount_client $MOUNT || error "(6) Fail to start client!"

	stat $DIR/$tdir/dummy | grep "Links: 1" > /dev/null ||
		error "(7) Fail to stat $DIR/$tdir/dummy"

	local dummyfid=$($LFS path2fid $DIR/$tdir/dummy)
	local dummyname=$($LFS fid2path $DIR $dummyfid)
	[ "$dummyname" == "$DIR/$tdir/dummy" ] ||
		error "(8) Fail to repair linkEA: $dummyfid $dummyname"
}
run_test 2c "LFSCK can find out and remove repeated linkEA entry"

test_2d()
{
	lfsck_prep 1 1

	#define OBD_FAIL_LFSCK_NO_LINKEA	0x161d
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x161d
	touch $DIR/$tdir/dummy

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	umount_client $MOUNT
	$START_NAMESPACE -r || error "(3) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^linkea_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(5) Fail to repair crashed linkEA: $repaired"

	run_e2fsck_on_mdt0

	mount_client $MOUNT || error "(6) Fail to start client!"

	stat $DIR/$tdir/dummy | grep "Links: 1" > /dev/null ||
		error "(7) Fail to stat $DIR/$tdir/dummy"

	local dummyfid=$($LFS path2fid $DIR/$tdir/dummy)
	local dummyname=$($LFS fid2path $DIR $dummyfid)
	[ "$dummyname" == "$DIR/$tdir/dummy" ] ||
		error "(8) Fail to repair linkEA: $dummyfid $dummyname"
}
run_test 2d "LFSCK can recover the missing linkEA entry"

test_2e()
{
	[ $MDSCOUNT -lt 2 ] &&
		skip "We need at least 2 MDSes for this test" && return

	check_mount_and_prep

	$LFS mkdir -i 1 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0 on MDT1"

	#define OBD_FAIL_LFSCK_LINKEA_CRASH	0x1603
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1603
	$LFS mkdir -i 0 $DIR/$tdir/d0/d1 || error "(2) Fail to mkdir d1 on MDT0"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	$START_NAMESPACE -r -A || error "(3) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^linkea_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(5) Fail to repair crashed linkEA: $repaired"

	local fid=$($LFS path2fid $DIR/$tdir/d0/d1)
	local name=$($LFS fid2path $DIR $fid)
	[ "$name" == "$DIR/$tdir/d0/d1" ] ||
		error "(6) Fail to repair linkEA: $fid $name"
}
run_test 2e "namespace LFSCK can verify remote object linkEA"

test_3()
{
	lfsck_prep 4 4

	mkdir $DIR/$tdir/dummy || error "(1) Fail to mkdir"
	ln $DIR/$tdir/d0/f0 $DIR/$tdir/dummy/f0 || error "(2) Fail to hardlink"
	ln $DIR/$tdir/d0/f1 $DIR/$tdir/dummy/f1 || error "(3) Fail to hardlink"

	$LFS mkdir -i 0 $DIR/$tdir/edir || error "(4) Fail to mkdir"
	touch $DIR/$tdir/edir/f0 || error "(5) Fail to touch"
	touch $DIR/$tdir/edir/f1 || error "(6) Fail to touch"

	#define OBD_FAIL_LFSCK_LINKEA_CRASH	0x1603
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1603
	ln $DIR/$tdir/edir/f0 $DIR/$tdir/edir/w0 || error "(7) Fail to hardlink"

	#define OBD_FAIL_LFSCK_LINKEA_MORE	0x1604
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1604
	ln $DIR/$tdir/edir/f1 $DIR/$tdir/edir/w1 || error "(8) Fail to hardlink"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	$START_NAMESPACE -r || error "(9) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(10) unexpected status"
	}

	local checked=$($SHOW_NAMESPACE |
			awk '/^checked_phase2/ { print $2 }')
	[ $checked -ge 4 ] ||
		error "(11) Fail to check multiple-linked object: $checked"

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^multiple_linked_repaired/ { print $2 }')
	[ $repaired -ge 2 ] ||
		error "(12) Fail to repair multiple-linked object: $repaired"
}
run_test 3 "LFSCK can verify multiple-linked objects"

test_4()
{
	[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
		skip "OI Scrub not implemented for ZFS" && return

	lfsck_prep 3 3
	cleanup_mount $MOUNT || error "(0.1) Fail to stop client!"
	stop $SINGLEMDS > /dev/null || error "(0.2) Fail to stop MDS!"

	mds_backup_restore $SINGLEMDS || error "(1) Fail to backup/restore!"
	echo "start $SINGLEMDS with disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MOUNT_OPTS_NOSCRUB > /dev/null ||
		error "(2) Fail to start MDS!"

	#define OBD_FAIL_LFSCK_DELAY2		0x1601
	do_facet $SINGLEMDS $LCTL set_param fail_val=1 fail_loc=0x1601
	$START_NAMESPACE -r || error "(4) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^flags/ { print \\\$2 }'" "inconsistent" 32 || {
		$SHOW_NAMESPACE
		error "(5) unexpected status"
	}

	local STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(6) Expect 'scanning-phase1', but got '$STATUS'"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(7) unexpected status"
	}

	FLAGS=$($SHOW_NAMESPACE | awk '/^flags/ { print $2 }')
	[ -z "$FLAGS" ] || error "(8) Expect empty flags, but got '$FLAGS'"

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^dirent_repaired/ { print $2 }')
	# for interop with old server
	[ -z "$repaired" ] &&
		repaired=$($SHOW_NAMESPACE |
			 awk '/^updated_phase1/ { print $2 }')

	[ $repaired -ge 9 ] ||
		error "(9) Fail to re-generate FID-in-dirent: $repaired"

	run_e2fsck_on_mdt0

	mount_client $MOUNT || error "(10) Fail to start client!"

	#define OBD_FAIL_FID_LOOKUP	0x1505
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1505
	ls $DIR/$tdir/ > /dev/null || error "(11) no FID-in-dirent."
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
}
run_test 4 "FID-in-dirent can be rebuilt after MDT file-level backup/restore"

test_5()
{
	[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
		skip "OI Scrub not implemented for ZFS" && return

	lfsck_prep 1 1 1
	cleanup_mount $MOUNT || error "(0.1) Fail to stop client!"
	stop $SINGLEMDS > /dev/null || error "(0.2) Fail to stop MDS!"

	mds_backup_restore $SINGLEMDS 1 || error "(1) Fail to backup/restore!"
	echo "start $SINGLEMDS with disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MOUNT_OPTS_NOSCRUB > /dev/null ||
		error "(2) Fail to start MDS!"

	#define OBD_FAIL_LFSCK_DELAY2		0x1601
	do_facet $SINGLEMDS $LCTL set_param fail_val=1 fail_loc=0x1601
	$START_NAMESPACE -r || error "(4) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^flags/ { print \\\$2 }'" "inconsistent,upgrade" 32 || {
		$SHOW_NAMESPACE
		error "(5) unexpected status"
	}

	local STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(6) Expect 'scanning-phase1', but got '$STATUS'"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(7) unexpected status"
	}

	FLAGS=$($SHOW_NAMESPACE | awk '/^flags/ { print $2 }')
	[ -z "$FLAGS" ] || error "(8) Expect empty flags, but got '$FLAGS'"

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^dirent_repaired/ { print $2 }')
	# for interop with old server
	[ -z "$repaired" ] &&
		repaired=$($SHOW_NAMESPACE |
			 awk '/^updated_phase1/ { print $2 }')

	[ $repaired -ge 2 ] ||
		error "(9) Fail to generate FID-in-dirent for IGIF: $repaired"

	run_e2fsck_on_mdt0

	mount_client $MOUNT || error "(10) Fail to start client!"

	#define OBD_FAIL_FID_LOOKUP	0x1505
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1505
	stat $DIR/$tdir/dummy > /dev/null || error "(11) no FID-in-LMA."

	ls $DIR/$tdir/ > /dev/null || error "(12) no FID-in-dirent."

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	local dummyfid=$($LFS path2fid $DIR/$tdir/dummy)
	local dummyname=$($LFS fid2path $DIR $dummyfid)
	[ "$dummyname" == "$DIR/$tdir/dummy" ] ||
		error "(13) Fail to generate linkEA: $dummyfid $dummyname"
}
run_test 5 "LFSCK can handle IGIF object upgrading"

test_6a() {
	lfsck_prep 5 5

	#define OBD_FAIL_LFSCK_DELAY1		0x1600
	do_facet $SINGLEMDS $LCTL set_param fail_val=1 fail_loc=0x1600
	$START_NAMESPACE -r || error "(2) Fail to start LFSCK for namespace!"

	local STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(3) Expect 'scanning-phase1', but got '$STATUS'"

	# Sleep 3 sec to guarantee at least one object processed by LFSCK
	sleep 3
	# Fail the LFSCK to guarantee there is at least one checkpoint
	#define OBD_FAIL_LFSCK_FATAL1		0x1608
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x80001608
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "failed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local POS0=$($SHOW_NAMESPACE |
		     awk '/^last_checkpoint_position/ { print $2 }' |
		     tr -d ',')

	#define OBD_FAIL_LFSCK_DELAY1		0x1600
	do_facet $SINGLEMDS $LCTL set_param fail_val=1 fail_loc=0x1600
	$START_NAMESPACE || error "(5) Fail to start LFSCK for namespace!"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(6) Expect 'scanning-phase1', but got '$STATUS'"

	local POS1=$($SHOW_NAMESPACE |
		     awk '/^latest_start_position/ { print $2 }' |
		     tr -d ',')
	[[ $POS0 -lt $POS1 ]] ||
		error "(7) Expect larger than: $POS0, but got $POS1"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(8) unexpected status"
	}
}
run_test 6a "LFSCK resumes from last checkpoint (1)"

test_6b() {
	lfsck_prep 5 5

	#define OBD_FAIL_LFSCK_DELAY2		0x1601
	do_facet $SINGLEMDS $LCTL set_param fail_val=1 fail_loc=0x1601
	$START_NAMESPACE -r || error "(2) Fail to start LFSCK for namespace!"

	local STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(3) Expect 'scanning-phase1', but got '$STATUS'"

	# Sleep 5 sec to guarantee that we are in the directory scanning
	sleep 5
	# Fail the LFSCK to guarantee there is at least one checkpoint
	#define OBD_FAIL_LFSCK_FATAL2		0x1609
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x80001609
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "failed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local O_POS0=$($SHOW_NAMESPACE |
		       awk '/^last_checkpoint_position/ { print $2 }' |
		       tr -d ',')

	local D_POS0=$($SHOW_NAMESPACE |
		       awk '/^last_checkpoint_position/ { print $4 }')

	#define OBD_FAIL_LFSCK_DELAY2		0x1601
	do_facet $SINGLEMDS $LCTL set_param fail_val=1 fail_loc=0x1601
	$START_NAMESPACE || error "(5) Fail to start LFSCK for namespace!"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(6) Expect 'scanning-phase1', but got '$STATUS'"

	local O_POS1=$($SHOW_NAMESPACE |
		       awk '/^latest_start_position/ { print $2 }' |
		       tr -d ',')
	local D_POS1=$($SHOW_NAMESPACE |
		       awk '/^latest_start_position/ { print $4 }')

	if [ "$D_POS0" == "N/A" -o "$D_POS1" == "N/A" ]; then
		[[ $O_POS0 -lt $O_POS1 ]] ||
			error "(7.1) $O_POS1 is not larger than $O_POS0"
	else
		[[ $D_POS0 -lt $D_POS1 ]] ||
			error "(7.2) $D_POS1 is not larger than $D_POS0"
	fi

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(8) unexpected status"
	}
}
run_test 6b "LFSCK resumes from last checkpoint (2)"

test_7a()
{
	lfsck_prep 5 5
	umount_client $MOUNT

	#define OBD_FAIL_LFSCK_DELAY2		0x1601
	do_facet $SINGLEMDS $LCTL set_param fail_val=1 fail_loc=0x1601
	$START_NAMESPACE -r || error "(2) Fail to start LFSCK for namespace!"

	local STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(3) Expect 'scanning-phase1', but got '$STATUS'"

	# Sleep 3 sec to guarantee at least one object processed by LFSCK
	sleep 3
	echo "stop $SINGLEMDS"
	stop $SINGLEMDS > /dev/null || error "(4) Fail to stop MDS!"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	echo "start $SINGLEMDS"
	start $SINGLEMDS $MDT_DEVNAME $MOUNT_OPTS_SCRUB > /dev/null ||
		error "(5) Fail to start MDS!"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 30 || {
		$SHOW_NAMESPACE
		error "(6) unexpected status"
	}
}
run_test 7a "non-stopped LFSCK should auto restarts after MDS remount (1)"

test_7b()
{
	lfsck_prep 2 2

	#define OBD_FAIL_LFSCK_LINKEA_MORE	0x1604
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1604
	for ((i = 0; i < 20; i++)); do
		touch $DIR/$tdir/dummy${i}
	done

	#define OBD_FAIL_LFSCK_DELAY3		0x1602
	do_facet $SINGLEMDS $LCTL set_param fail_val=1 fail_loc=0x1602
	$START_NAMESPACE -r || error "(3) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "scanning-phase2" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	umount_client $MOUNT
	echo "stop $SINGLEMDS"
	stop $SINGLEMDS > /dev/null || error "(5) Fail to stop MDS!"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	echo "start $SINGLEMDS"
	start $SINGLEMDS $MDT_DEVNAME $MOUNT_OPTS_SCRUB > /dev/null ||
		error "(6) Fail to start MDS!"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 30 || {
		$SHOW_NAMESPACE
		error "(7) unexpected status"
	}
}
run_test 7b "non-stopped LFSCK should auto restarts after MDS remount (2)"

test_8()
{
	echo "formatall"
	formatall > /dev/null
	echo "setupall"
	setupall > /dev/null

	lfsck_prep 20 20

	local STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "init" ] ||
		error "(2) Expect 'init', but got '$STATUS'"

	#define OBD_FAIL_LFSCK_LINKEA_CRASH	0x1603
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1603
	mkdir $DIR/$tdir/crashed

	#define OBD_FAIL_LFSCK_LINKEA_MORE	0x1604
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1604
	for ((i = 0; i < 5; i++)); do
		touch $DIR/$tdir/dummy${i}
	done

	umount_client $MOUNT || error "(3) Fail to stop client!"

	#define OBD_FAIL_LFSCK_DELAY2		0x1601
	do_facet $SINGLEMDS $LCTL set_param fail_val=2 fail_loc=0x1601
	$START_NAMESPACE || error "(4) Fail to start LFSCK for namespace!"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(5) Expect 'scanning-phase1', but got '$STATUS'"

	$STOP_LFSCK || error "(6) Fail to stop LFSCK!"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "stopped" ] ||
		error "(7) Expect 'stopped', but got '$STATUS'"

	$START_NAMESPACE || error "(8) Fail to start LFSCK for namespace!"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(9) Expect 'scanning-phase1', but got '$STATUS'"

	#define OBD_FAIL_LFSCK_FATAL2		0x1609
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x80001609
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "failed" 32 || {
		$SHOW_NAMESPACE
		error "(10) unexpected status"
	}

	#define OBD_FAIL_LFSCK_DELAY1		0x1600
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1600
	$START_NAMESPACE || error "(11) Fail to start LFSCK for namespace!"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(12) Expect 'scanning-phase1', but got '$STATUS'"

	#define OBD_FAIL_LFSCK_CRASH		0x160a
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x160a
	sleep 5

	echo "stop $SINGLEMDS"
	stop $SINGLEMDS > /dev/null || error "(13) Fail to stop MDS!"

	#define OBD_FAIL_LFSCK_NO_AUTO		0x160b
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x160b

	echo "start $SINGLEMDS"
	start $SINGLEMDS $MDT_DEVNAME $MOUNT_OPTS_SCRUB > /dev/null ||
		error "(14) Fail to start MDS!"

	local timeout=$(max_recovery_time)
	local timer=0

	while [ $timer -lt $timeout ]; do
		STATUS=$(do_facet $SINGLEMDS "$LCTL get_param -n \
			mdt.${MDT_DEV}.recovery_status |
			awk '/^status/ { print \\\$2 }'")
		[ "$STATUS" != "RECOVERING" ] && break;
		sleep 1
		timer=$((timer + 1))
	done

	[ $timer != $timeout ] ||
		error "(14.1) recovery timeout"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "crashed" ] ||
		error "(15) Expect 'crashed', but got '$STATUS'"

	#define OBD_FAIL_LFSCK_DELAY2		0x1601
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1601
	$START_NAMESPACE || error "(16) Fail to start LFSCK for namespace!"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(17) Expect 'scanning-phase1', but got '$STATUS'"

	echo "stop $SINGLEMDS"
	stop $SINGLEMDS > /dev/null || error "(18) Fail to stop MDS!"

	#define OBD_FAIL_LFSCK_NO_AUTO		0x160b
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x160b

	echo "start $SINGLEMDS"
	start $SINGLEMDS $MDT_DEVNAME $MOUNT_OPTS_SCRUB > /dev/null ||
		error "(19) Fail to start MDS!"

	timer=0
	while [ $timer -lt $timeout ]; do
		STATUS=$(do_facet $SINGLEMDS "$LCTL get_param -n \
			mdt.${MDT_DEV}.recovery_status |
			awk '/^status/ { print \\\$2 }'")
		[ "$STATUS" != "RECOVERING" ] && break;
		sleep 1
		timer=$((timer + 1))
	done

	[ $timer != $timeout ] ||
		error "(19.1) recovery timeout"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "paused" ] ||
		error "(20) Expect 'paused', but got '$STATUS'"

	echo "stop $SINGLEMDS"
	stop $SINGLEMDS > /dev/null || error "(20.1) Fail to stop MDS!"

	echo "start $SINGLEMDS without resume LFSCK"
	start $SINGLEMDS $MDT_DEVNAME $MOUNT_OPTS_SKIP_LFSCK > /dev/null ||
		error "(20.2) Fail to start MDS!"

	timer=0
	while [ $timer -lt $timeout ]; do
		STATUS=$(do_facet $SINGLEMDS "$LCTL get_param -n \
			mdt.${MDT_DEV}.recovery_status |
			awk '/^status/ { print \\\$2 }'")
		[ "$STATUS" != "RECOVERING" ] && break;
		sleep 1
		timer=$((timer + 1))
	done

	[ $timer != $timeout ] ||
		error "(20.3) recovery timeout"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "paused" ] ||
		error "(20.4) Expect 'paused', but got '$STATUS'"

	#define OBD_FAIL_LFSCK_DELAY3		0x1602
	do_facet $SINGLEMDS $LCTL set_param fail_val=2 fail_loc=0x1602

	$START_NAMESPACE || error "(21) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "scanning-phase2" 32 || {
		$SHOW_NAMESPACE
		error "(22) unexpected status"
	}

	local FLAGS=$($SHOW_NAMESPACE | awk '/^flags/ { print $2 }')
	[ "$FLAGS" == "scanned-once,inconsistent" ] ||
		error "(23) Expect 'scanned-once,inconsistent',but got '$FLAGS'"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(24) unexpected status"
	}

	FLAGS=$($SHOW_NAMESPACE | awk '/^flags/ { print $2 }')
	[ -z "$FLAGS" ] || error "(25) Expect empty flags, but got '$FLAGS'"
}
run_test 8 "LFSCK state machine"

test_9a() {
	if [ -z "$(grep "processor.*: 1" /proc/cpuinfo)" ]; then
		skip "Testing on UP system, the speed may be inaccurate."
		return 0
	fi

	[[ $server_version -ge $(version_code 2.7.50) ]] ||
		{ skip "Need MDS version >= 2.7.50"; return; }

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/lfsck || error "(1) Fail to mkdir lfsck"
	$LFS setstripe -c 1 -i -1 $DIR/$tdir/lfsck
	createmany -o $DIR/$tdir/lfsck/f 5000

	local BASE_SPEED1=100
	local RUN_TIME1=10
	$START_LAYOUT -r -s $BASE_SPEED1 || error "(2) Fail to start LFSCK!"

	sleep $RUN_TIME1
	STATUS=$($SHOW_LAYOUT | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(3) Expect 'scanning-phase1', but got '$STATUS'"

	local SPEED=$($SHOW_LAYOUT |
		      awk '/^average_speed_phase1/ { print $2 }')

	# There may be time error, normally it should be less than 2 seconds.
	# We allow another 20% schedule error.
	local TIME_DIFF=2
	# MAX_MARGIN = 1.2 = 12 / 10
	local MAX_SPEED=$((BASE_SPEED1 * (RUN_TIME1 + TIME_DIFF) / \
			   RUN_TIME1 * 12 / 10))
	[ $SPEED -lt $MAX_SPEED ] ||
		error "(4) Got speed $SPEED, expected less than $MAX_SPEED"

	# adjust speed limit
	local BASE_SPEED2=300
	local RUN_TIME2=10
	do_facet $SINGLEMDS \
		$LCTL set_param -n mdd.${MDT_DEV}.lfsck_speed_limit $BASE_SPEED2
	sleep $RUN_TIME2

	SPEED=$($SHOW_LAYOUT | awk '/^average_speed_phase1/ { print $2 }')
	# MIN_MARGIN = 0.8 = 8 / 10
	local MIN_SPEED=$(((BASE_SPEED1 * (RUN_TIME1 - TIME_DIFF) + \
			    BASE_SPEED2 * (RUN_TIME2 - TIME_DIFF)) / \
			   (RUN_TIME1 + RUN_TIME2) * 8 / 10))
	[ $SPEED -gt $MIN_SPEED ] || {
		if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
			error_ignore LU-5624 \
			"(5.1) Got speed $SPEED, expected more than $MIN_SPEED"
		else
			error \
			"(5.2) Got speed $SPEED, expected more than $MIN_SPEED"
		fi
	}

	# MAX_MARGIN = 1.2 = 12 / 10
	MAX_SPEED=$(((BASE_SPEED1 * (RUN_TIME1 + TIME_DIFF) + \
		      BASE_SPEED2 * (RUN_TIME2 + TIME_DIFF)) / \
		     (RUN_TIME1 + RUN_TIME2) * 12 / 10))
	[ $SPEED -lt $MAX_SPEED ] ||
		error "(6) Got speed $SPEED, expected less than $MAX_SPEED"

	do_facet $SINGLEMDS \
		$LCTL set_param -n mdd.${MDT_DEV}.lfsck_speed_limit 0

	wait_update_facet $SINGLEMDS \
		"$LCTL get_param -n mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 30 ||
		error "(7) Failed to get expected 'completed'"
}
run_test 9a "LFSCK speed control (1)"

test_9b() {
	if [ -z "$(grep "processor.*: 1" /proc/cpuinfo)" ]; then
		skip "Testing on UP system, the speed may be inaccurate."
		return 0
	fi

	[[ $server_version -ge $(version_code 2.7.50) ]] ||
		{ skip "Need MDS version >= 2.7.50"; return; }

	lfsck_prep 0 0

	echo "Preparing another 50 * 50 files (with error) at $(date)."
	#define OBD_FAIL_LFSCK_LINKEA_MORE	0x1604
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1604
	createmany -d $DIR/$tdir/d 50
	createmany -m $DIR/$tdir/f 50
	for ((i = 0; i < 50; i++)); do
		createmany -m $DIR/$tdir/d${i}/f 50 > /dev/null
	done

	#define OBD_FAIL_LFSCK_NO_DOUBLESCAN	0x160c
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x160c
	$START_NAMESPACE -r || error "(4) Fail to start LFSCK!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "stopped" 10 || {
		$SHOW_NAMESPACE
		error "(5) unexpected status"
	}

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	echo "Prepared at $(date)."

	local BASE_SPEED1=50
	local RUN_TIME1=10
	$START_NAMESPACE -s $BASE_SPEED1 || error "(6) Fail to start LFSCK!"

	sleep $RUN_TIME1
	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase2" ] ||
		error "(7) Expect 'scanning-phase2', but got '$STATUS'"

	local SPEED=$($SHOW_NAMESPACE |
		      awk '/^average_speed_phase2/ { print $2 }')
	# There may be time error, normally it should be less than 2 seconds.
	# We allow another 20% schedule error.
	local TIME_DIFF=2
	# MAX_MARGIN = 1.2 = 12 / 10
	local MAX_SPEED=$((BASE_SPEED1 * (RUN_TIME1 + TIME_DIFF) / \
			  RUN_TIME1 * 12 / 10))
	[ $SPEED -lt $MAX_SPEED ] ||
		error "(8) Got speed $SPEED, expected less than $MAX_SPEED"

	# adjust speed limit
	local BASE_SPEED2=150
	local RUN_TIME2=10
	do_facet $SINGLEMDS \
		$LCTL set_param -n mdd.${MDT_DEV}.lfsck_speed_limit $BASE_SPEED2
	sleep $RUN_TIME2

	SPEED=$($SHOW_NAMESPACE | awk '/^average_speed_phase2/ { print $2 }')
	# MIN_MARGIN = 0.8 = 8 / 10
	local MIN_SPEED=$(((BASE_SPEED1 * (RUN_TIME1 - TIME_DIFF) + \
			    BASE_SPEED2 * (RUN_TIME2 - TIME_DIFF)) / \
			   (RUN_TIME1 + RUN_TIME2) * 8 / 10))
	[ $SPEED -gt $MIN_SPEED ] || {
		if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
			error_ignore LU-5624 \
			"(9.1) Got speed $SPEED, expected more than $MIN_SPEED"
		else
			error \
			"(9.2) Got speed $SPEED, expected more than $MIN_SPEED"
		fi
	}

	# MAX_MARGIN = 1.2 = 12 / 10
	MAX_SPEED=$(((BASE_SPEED1 * (RUN_TIME1 + TIME_DIFF) + \
		      BASE_SPEED2 * (RUN_TIME2 + TIME_DIFF)) / \
		     (RUN_TIME1 + RUN_TIME2) * 12 / 10))
	[ $SPEED -lt $MAX_SPEED ] ||
		error "(10) Got speed $SPEED, expected less than $MAX_SPEED"

	do_facet $SINGLEMDS \
		$LCTL set_param -n mdd.${MDT_DEV}.lfsck_speed_limit 0
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(11) unexpected status"
	}
}
run_test 9b "LFSCK speed control (2)"

test_10()
{
	[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
		skip "lookup(..)/linkea on ZFS issue" && return

	lfsck_prep 1 1

	echo "Preparing more files with error at $(date)."
	#define OBD_FAIL_LFSCK_LINKEA_CRASH	0x1603
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1603

	for ((i = 0; i < 1000; i = $((i+2)))); do
		mkdir -p $DIR/$tdir/d${i}
		touch $DIR/$tdir/f${i}
		createmany -m $DIR/$tdir/d${i}/f 5 > /dev/null
	done

	#define OBD_FAIL_LFSCK_LINKEA_MORE	0x1604
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1604

	for ((i = 1; i < 1000; i = $((i+2)))); do
		mkdir -p $DIR/$tdir/d${i}
		touch $DIR/$tdir/f${i}
		createmany -m $DIR/$tdir/d${i}/f 5 > /dev/null
	done

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	echo "Prepared at $(date)."

	ln $DIR/$tdir/f200 $DIR/$tdir/d200/dummy

	umount_client $MOUNT
	mount_client $MOUNT || error "(3) Fail to start client!"

	$START_NAMESPACE -r -s 100 || error "(5) Fail to start LFSCK!"

	sleep 10
	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(6) Expect 'scanning-phase1', but got '$STATUS'"

	ls -ailR $MOUNT > /dev/null || error "(7) Fail to ls!"

	touch $DIR/$tdir/d198/a0 || error "(8) Fail to touch!"

	mkdir $DIR/$tdir/d199/a1 || error "(9) Fail to mkdir!"

	unlink $DIR/$tdir/f200 || error "(10) Fail to unlink!"

	rm -rf $DIR/$tdir/d201 || error "(11) Fail to rmdir!"

	mv $DIR/$tdir/f202 $DIR/$tdir/d203/ || error "(12) Fail to rename!"

	ln $DIR/$tdir/f204 $DIR/$tdir/d205/a3 || error "(13) Fail to hardlink!"

	ln -s $DIR/$tdir/d206 $DIR/$tdir/d207/a4 ||
		error "(14) Fail to softlink!"

	STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(15) Expect 'scanning-phase1', but got '$STATUS'"

	do_facet $SINGLEMDS \
		$LCTL set_param -n mdd.${MDT_DEV}.lfsck_speed_limit 0
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(16) unexpected status"
	}
}
run_test 10 "System is available during LFSCK scanning"

# remove LAST_ID
ost_remove_lastid() {
	local ost=$1
	local idx=$2
	local rcmd="do_facet ost${ost}"

	echo "remove LAST_ID on ost${ost}: idx=${idx}"

	# step 1: local mount
	mount_fstype ost${ost} || return 1
	# step 2: remove the specified LAST_ID
	${rcmd} rm -fv $(facet_mntpt ost${ost})/O/${idx}/{LAST_ID,d0/0}
	# step 3: umount
	unmount_fstype ost${ost} || return 2
}

test_11a() {
	check_mount_and_prep
	$SETSTRIPE -c 1 -i 0 $DIR/$tdir
	createmany -o $DIR/$tdir/f 64 || error "(0) Fail to create 64 files."

	echo "stopall"
	stopall > /dev/null

	ost_remove_lastid 1 0 || error "(1) Fail to remove LAST_ID"

	start ost1 $(ostdevname 1) $MOUNT_OPTS_NOSCRUB > /dev/null ||
		error "(2) Fail to start ost1"

	#define OBD_FAIL_LFSCK_DELAY4		0x160e
	do_facet ost1 $LCTL set_param fail_val=3 fail_loc=0x160e

	echo "trigger LFSCK for layout on ost1 to rebuild the LAST_ID(s)"
	$START_LAYOUT_ON_OST -r || error "(4) Fail to start LFSCK on OST!"

	wait_update_facet ost1 "$LCTL get_param -n \
		obdfilter.${OST_DEV}.lfsck_layout |
		awk '/^flags/ { print \\\$2 }'" "crashed_lastid" 60 || {
		$SHOW_LAYOUT_ON_OST
		error "(5) unexpected status"
	}

	do_facet ost1 $LCTL set_param fail_val=0 fail_loc=0

	wait_update_facet ost1 "$LCTL get_param -n \
		obdfilter.${OST_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT_ON_OST
		error "(6) unexpected status"
	}

	echo "the LAST_ID(s) should have been rebuilt"
	FLAGS=$($SHOW_LAYOUT_ON_OST | awk '/^flags/ { print $2 }')
	[ -z "$FLAGS" ] || error "(7) Expect empty flags, but got '$FLAGS'"
}
run_test 11a "LFSCK can rebuild lost last_id"

test_11b() {
	check_mount_and_prep
	$SETSTRIPE -c 1 -i 0 $DIR/$tdir

	echo "set fail_loc=0x160d to skip the updating LAST_ID on-disk"
	#define OBD_FAIL_LFSCK_SKIP_LASTID	0x160d
	do_facet ost1 $LCTL set_param fail_loc=0x160d

	local count=$(precreated_ost_obj_count 0 0)

	createmany -o $DIR/$tdir/f $((count + 32))

	local proc_path="${FSNAME}-OST0000-osc-MDT0000"
	local seq=$(do_facet mds1 $LCTL get_param -n \
		    osp.${proc_path}.prealloc_last_seq)
	local lastid1=$(do_facet ost1 "lctl get_param -n \
		obdfilter.${ost1_svc}.last_id" | grep $seq |
		awk -F: '{ print $2 }')

	umount_client $MOUNT
	stop ost1 || error "(1) Fail to stop ost1"

	#define OBD_FAIL_OST_ENOSPC              0x215
	do_facet ost1 $LCTL set_param fail_loc=0x215

	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS ||
		error "(2) Fail to start ost1"

	for ((i = 0; i < 60; i++)); do
		lastid2=$(do_facet ost1 "lctl get_param -n \
			obdfilter.${ost1_svc}.last_id" | grep $seq |
			awk -F: '{ print $2 }')
		[ ! -z $lastid2 ] && break;
		sleep 1
	done

	echo "the on-disk LAST_ID should be smaller than the expected one"
	[ $lastid1 -gt $lastid2 ] ||
		error "(4) expect lastid1 [ $lastid1 ] > lastid2 [ $lastid2 ]"

	echo "trigger LFSCK for layout on ost1 to rebuild the on-disk LAST_ID"
	$START_LAYOUT_ON_OST -r || error "(5) Fail to start LFSCK on OST!"

	wait_update_facet ost1 "$LCTL get_param -n \
		obdfilter.${OST_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT_ON_OST
		error "(6) unexpected status"
	}

	stop ost1 || error "(7) Fail to stop ost1"

	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS ||
		error "(8) Fail to start ost1"

	echo "the on-disk LAST_ID should have been rebuilt"
	wait_update_facet ost1 "$LCTL get_param -n \
		obdfilter.${ost1_svc}.last_id | grep $seq |
		awk -F: '{ print \\\$2 }'" "$lastid1" 60 || {
		do_facet ost1 $LCTL get_param -n \
		obdfilter.${ost1_svc}.last_id
		error "(9) expect lastid1 $seq:$lastid1"
	}

	do_facet ost1 $LCTL set_param fail_loc=0
	stopall || error "(10) Fail to stopall"
}
run_test 11b "LFSCK can rebuild crashed last_id"

test_12() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "We need at least 2 MDSes for test_12" && return

	check_mount_and_prep
	for k in $(seq $MDSCOUNT); do
		$LFS mkdir -i $((k - 1)) $DIR/$tdir/${k}
		createmany -o $DIR/$tdir/${k}/f 100 ||
			error "(0) Fail to create 100 files."
	done

	echo "Start namespace LFSCK on all targets by single command (-s 1)."
	do_facet mds1 $LCTL lfsck_start -M ${FSNAME}-MDT0000 -t namespace -A \
		-s 1 -r || error "(2) Fail to start LFSCK on all devices!"

	echo "All the LFSCK targets should be in 'scanning-phase1' status."
	for k in $(seq $MDSCOUNT); do
		local STATUS=$(do_facet mds${k} $LCTL get_param -n \
				mdd.$(facet_svc mds${k}).lfsck_namespace |
				awk '/^status/ { print $2 }')
		[ "$STATUS" == "scanning-phase1" ] ||
		error "(3) MDS${k} Expect 'scanning-phase1', but got '$STATUS'"
	done

	echo "Stop namespace LFSCK on all targets by single lctl command."
	do_facet mds1 $LCTL lfsck_stop -M ${FSNAME}-MDT0000 -A ||
		error "(4) Fail to stop LFSCK on all devices!"

	echo "All the LFSCK targets should be in 'stopped' status."
	for k in $(seq $MDSCOUNT); do
		local STATUS=$(do_facet mds${k} $LCTL get_param -n \
				mdd.$(facet_svc mds${k}).lfsck_namespace |
				awk '/^status/ { print $2 }')
		[ "$STATUS" == "stopped" ] ||
			error "(5) MDS${k} Expect 'stopped', but got '$STATUS'"
	done

	echo "Re-start namespace LFSCK on all targets by single command (-s 0)."
	do_facet mds1 $LCTL lfsck_start -M ${FSNAME}-MDT0000 -t namespace -A \
		-s 0 -r || error "(6) Fail to start LFSCK on all devices!"

	echo "All the LFSCK targets should be in 'completed' status."
	for k in $(seq $MDSCOUNT); do
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_namespace |
			awk '/^status/ { print \\\$2 }'" "completed" 8 ||
			error "(7) MDS${k} is not the expected 'completed'"
	done

	start_full_debug_logging

	echo "Start layout LFSCK on all targets by single command (-s 1)."
	do_facet mds1 $LCTL lfsck_start -M ${FSNAME}-MDT0000 -t layout -A \
		-s 1 -r || error "(8) Fail to start LFSCK on all devices!"

	echo "All the LFSCK targets should be in 'scanning-phase1' status."
	for k in $(seq $MDSCOUNT); do
		local STATUS=$(do_facet mds${k} $LCTL get_param -n \
				mdd.$(facet_svc mds${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$STATUS" == "scanning-phase1" ] ||
		error "(9) MDS${k} Expect 'scanning-phase1', but got '$STATUS'"
	done

	echo "Stop layout LFSCK on all targets by single lctl command."
	do_facet mds1 $LCTL lfsck_stop -M ${FSNAME}-MDT0000 -A ||
		error "(10) Fail to stop LFSCK on all devices!"

	echo "All the LFSCK targets should be in 'stopped' status."
	for k in $(seq $MDSCOUNT); do
		local STATUS=$(do_facet mds${k} $LCTL get_param -n \
				mdd.$(facet_svc mds${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$STATUS" == "stopped" ] ||
			error "(11) MDS${k} Expect 'stopped', but got '$STATUS'"
	done

	for k in $(seq $OSTCOUNT); do
		local STATUS=$(do_facet ost${k} $LCTL get_param -n \
				obdfilter.$(facet_svc ost${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$STATUS" == "stopped" ] ||
			error "(12) OST${k} Expect 'stopped', but got '$STATUS'"
	done

	echo "Re-start layout LFSCK on all targets by single command (-s 0)."
	do_facet mds1 $LCTL lfsck_start -M ${FSNAME}-MDT0000 -t layout -A \
		-s 0 -r || error "(13) Fail to start LFSCK on all devices!"

	echo "All the LFSCK targets should be in 'completed' status."
	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" 32 ||
			error "(14) MDS${k} is not the expected 'completed'"
	done

	stop_full_debug_logging
}
run_test 12 "single command to trigger LFSCK on all devices"

test_13() {
	echo "#####"
	echo "The lmm_oi in layout EA should be consistent with the MDT-object"
	echo "FID; otherwise, the LFSCK should re-generate the lmm_oi from the"
	echo "MDT-object FID."
	echo "#####"

	check_mount_and_prep

	echo "Inject failure stub to simulate bad lmm_oi"
	#define OBD_FAIL_LFSCK_BAD_LMMOI	0x160f
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x160f
	createmany -o $DIR/$tdir/f 32
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	echo "Trigger layout LFSCK to find out the bad lmm_oi and fix them"
	$START_LAYOUT -r || error "(1) Fail to start LFSCK for layout!"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT
		error "(2) unexpected status"
	}

	local repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_others/ { print $2 }')
	[ $repaired -eq 32 ] ||
		error "(3) Fail to repair crashed lmm_oi: $repaired"
}
run_test 13 "LFSCK can repair crashed lmm_oi"

test_14() {
	echo "#####"
	echo "The OST-object referenced by the MDT-object should be there;"
	echo "otherwise, the LFSCK should re-create the missing OST-object."
	echo "#####"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	echo "Inject failure stub to simulate dangling referenced MDT-object"
	#define OBD_FAIL_LFSCK_DANGLING	0x1610
	do_facet ost1 $LCTL set_param fail_loc=0x1610
	local count=$(precreated_ost_obj_count 0 0)

	createmany -o $DIR/$tdir/f $((count + 31))
	touch $DIR/$tdir/guard
	do_facet ost1 $LCTL set_param fail_loc=0

	start_full_debug_logging

	# exhaust other pre-created dangling cases
	count=$(precreated_ost_obj_count 0 0)
	createmany -o $DIR/$tdir/a $count ||
		error "(0) Fail to create $count files."

	echo "'ls' should fail because of dangling referenced MDT-object"
	ls -ail $DIR/$tdir > /dev/null 2>&1 && error "(1) ls should fail."

	echo "Trigger layout LFSCK to find out dangling reference"
	$START_LAYOUT -r || error "(2) Fail to start LFSCK for layout!"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT
		error "(3) unexpected status"
	}

	local repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_dangling/ { print $2 }')
	[ $repaired -ge 32 ] ||
		error "(4) Fail to repair dangling reference: $repaired"

	echo "'stat' should fail because of not repair dangling by default"
	stat $DIR/$tdir/guard > /dev/null 2>&1 && error "(5) stat should fail"

	echo "Trigger layout LFSCK to repair dangling reference"
	$START_LAYOUT -r -c || error "(6) Fail to start LFSCK for layout!"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT
		error "(7) unexpected status"
	}

	# There may be some async LFSCK updates in processing, wait for
	# a while until the target reparation has been done. LU-4970.

	echo "'stat' should success after layout LFSCK repairing"
	wait_update_facet client "stat $DIR/$tdir/guard |
		awk '/Size/ { print \\\$2 }'" "0" 32 || {
		stat $DIR/$tdir/guard
		$SHOW_LAYOUT
		error "(8) unexpected size"
	}

	repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_dangling/ { print $2 }')
	[ $repaired -ge 32 ] ||
		error "(9) Fail to repair dangling reference: $repaired"

	stop_full_debug_logging
}
run_test 14 "LFSCK can repair MDT-object with dangling reference"

test_15a() {
	echo "#####"
	echo "If the OST-object referenced by the MDT-object back points"
	echo "to some non-exist MDT-object, then the LFSCK should repair"
	echo "the OST-object to back point to the right MDT-object."
	echo "#####"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	echo "Inject failure stub to make the OST-object to back point to"
	echo "non-exist MDT-object."
	#define OBD_FAIL_LFSCK_UNMATCHED_PAIR1	0x1611

	do_facet ost1 $LCTL set_param fail_loc=0x1611
	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=1
	cancel_lru_locks osc
	do_facet ost1 $LCTL set_param fail_loc=0

	echo "Trigger layout LFSCK to find out unmatched pairs and fix them"
	$START_LAYOUT -r || error "(1) Fail to start LFSCK for layout!"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT
		error "(2) unexpected status"
	}

	local repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_unmatched_pair/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(3) Fail to repair unmatched pair: $repaired"
}
run_test 15a "LFSCK can repair unmatched MDT-object/OST-object pairs (1)"

test_15b() {
	echo "#####"
	echo "If the OST-object referenced by the MDT-object back points"
	echo "to other MDT-object that doesn't recognize the OST-object,"
	echo "then the LFSCK should repair it to back point to the right"
	echo "MDT-object (the first one)."
	echo "#####"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir
	dd if=/dev/zero of=$DIR/$tdir/guard bs=1M count=1
	cancel_lru_locks osc

	echo "Inject failure stub to make the OST-object to back point to"
	echo "other MDT-object"

	#define OBD_FAIL_LFSCK_UNMATCHED_PAIR2	0x1612
	do_facet ost1 $LCTL set_param fail_loc=0x1612
	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=1
	cancel_lru_locks osc
	do_facet ost1 $LCTL set_param fail_loc=0

	echo "Trigger layout LFSCK to find out unmatched pairs and fix them"
	$START_LAYOUT -r || error "(1) Fail to start LFSCK for layout!"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT
		error "(2) unexpected status"
	}

	local repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_unmatched_pair/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(3) Fail to repair unmatched pair: $repaired"
}
run_test 15b "LFSCK can repair unmatched MDT-object/OST-object pairs (2)"

test_15c() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "We need at least 2 MDSes for this test" && return

	[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.7.55) ] &&
		skip "Skip the test after 2.7.55 see LU-6437" && return

	echo "#####"
	echo "According to current metadata migration implementation,"
	echo "before the old MDT-object is removed, both the new MDT-object"
	echo "and old MDT-object will reference the same LOV layout. Then if"
	echo "the layout LFSCK finds the new MDT-object by race, it will"
	echo "regard related OST-object(s) as multiple referenced case, and"
	echo "will try to create new OST-object(s) for the new MDT-object."
	echo "To avoid such trouble, the layout LFSCK needs to lock the old"
	echo "MDT-object before confirm the multiple referenced case."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 1 $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/a1
	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=1M count=1
	cancel_lru_locks osc

	echo "Inject failure stub on MDT1 to delay the migration"

	#define OBD_FAIL_MIGRATE_DELAY			0x1803
	do_facet mds2 $LCTL set_param fail_val=5 fail_loc=0x1803
	echo "Migrate $DIR/$tdir/a1 from MDT1 to MDT0 with delay"
	$LFS migrate -m 0 $DIR/$tdir/a1 &

	sleep 1
	echo "Trigger layout LFSCK to race with the migration"
	$START_LAYOUT -A -r || error "(1) Fail to start layout LFSCK!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" $LTIME ||
			error "(2) MDS${k} is not the expected 'completed'"
	done

	do_facet mds2 $LCTL set_param fail_loc=0 fail_val=0
	local repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_unmatched_pair/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(3) Fail to repair unmatched pair: $repaired"

	repaired=$($SHOW_LAYOUT |
		   awk '/^repaired_multiple_referenced/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(4) Unexpectedly repaird multiple references: $repaired"
}
run_test 15c "LFSCK can repair unmatched MDT-object/OST-object pairs (3)"

test_16() {
	echo "#####"
	echo "If the OST-object's owner information does not match the owner"
	echo "information stored in the MDT-object, then the LFSCK trust the"
	echo "MDT-object and update the OST-object's owner information."
	echo "#####"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir
	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=1
	cancel_lru_locks osc

	echo "Inject failure stub to skip OST-object owner changing"
	#define OBD_FAIL_LFSCK_BAD_OWNER	0x1613
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1613
	chown 1.1 $DIR/$tdir/f0
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	echo "Trigger layout LFSCK to find out inconsistent OST-object owner"
	echo "and fix them"

	$START_LAYOUT -r || error "(1) Fail to start LFSCK for layout!"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT
		error "(2) unexpected status"
	}

	local repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_inconsistent_owner/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(3) Fail to repair inconsistent owner: $repaired"
}
run_test 16 "LFSCK can repair inconsistent MDT-object/OST-object owner"

test_17() {
	echo "#####"
	echo "If more than one MDT-objects reference the same OST-object,"
	echo "and the OST-object only recognizes one MDT-object, then the"
	echo "LFSCK should create new OST-objects for such non-recognized"
	echo "MDT-objects."
	echo "#####"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	echo "Inject failure stub to make two MDT-objects to refernce"
	echo "the OST-object"

	#define OBD_FAIL_LFSCK_MULTIPLE_REF	0x1614
	do_facet $SINGLEMDS $LCTL set_param fail_val=0 fail_loc=0x1614

	dd if=/dev/zero of=$DIR/$tdir/guard bs=1M count=1
	cancel_lru_locks osc

	createmany -o $DIR/$tdir/f 1

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0

	cancel_lru_locks mdc
	cancel_lru_locks osc

	echo "$DIR/$tdir/f0 and $DIR/$tdir/guard use the same OST-objects"
	local size=$(ls -l $DIR/$tdir/f0 | awk '{ print $5 }')
	[ $size -eq 1048576 ] ||
		error "(1) f0 (wrong) size should be 1048576, but got $size"

	echo "Trigger layout LFSCK to find out multiple refenced MDT-objects"
	echo "and fix them"

	$START_LAYOUT -r || error "(2) Fail to start LFSCK for layout!"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT
		error "(3) unexpected status"
	}

	local repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_multiple_referenced/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(4) Fail to repair multiple references: $repaired"

	echo "$DIR/$tdir/f0 and $DIR/$tdir/guard should use diff OST-objects"
	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=2 ||
		error "(5) Fail to write f0."
	size=$(ls -l $DIR/$tdir/guard | awk '{ print $5 }')
	[ $size -eq 1048576 ] ||
		error "(6) guard size should be 1048576, but got $size"
}
run_test 17 "LFSCK can repair multiple references"

$LCTL set_param debug=+cache > /dev/null

test_18a() {
	echo "#####"
	echo "The target MDT-object is there, but related stripe information"
	echo "is lost or partly lost. The LFSCK should regenerate the missing"
	echo "layout EA entries."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 -S 1M $DIR/$tdir/a1
	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=1M count=2

	local saved_size=$(ls -il $DIR/$tdir/a1/f1 | awk '{ print $6 }')

	$LFS path2fid $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS mkdir -i 1 $DIR/$tdir/a2
		$LFS setstripe -c 2 -i 1 -S 1M $DIR/$tdir/a2
		dd if=/dev/zero of=$DIR/$tdir/a2/f2 bs=1M count=2
		$LFS path2fid $DIR/$tdir/a2/f2
		$LFS getstripe $DIR/$tdir/a2/f2
	fi

	cancel_lru_locks osc

	echo "Inject failure, to make the MDT-object lost its layout EA"
	#define OBD_FAIL_LFSCK_LOST_STRIPE 0x1615
	do_facet mds1 $LCTL set_param fail_loc=0x1615
	chown 1.1 $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0x1615
		chown 1.1 $DIR/$tdir/a2/f2
	fi

	sync
	sleep 2

	do_facet mds1 $LCTL set_param fail_loc=0
	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0
	fi

	cancel_lru_locks mdc
	cancel_lru_locks osc

	echo "The file size should be incorrect since layout EA is lost"
	local cur_size=$(ls -il $DIR/$tdir/a1/f1 | awk '{ print $6 }')
	[ "$cur_size" != "$saved_size" ] ||
		error "(1) Expect incorrect file1 size"

	if [ $MDSCOUNT -ge 2 ]; then
		cur_size=$(ls -il $DIR/$tdir/a2/f2 | awk '{ print $6 }')
		[ "$cur_size" != "$saved_size" ] ||
			error "(2) Expect incorrect file2 size"
	fi

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o || error "(3) Fail to start LFSCK for layout!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" $LTIME ||
			error "(4) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		local cur_status=$(do_facet ost${k} $LCTL get_param -n \
				obdfilter.$(facet_svc ost${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(5) OST${k} Expect 'completed', but got '$cur_status'"
	done

	local repaired=$(do_facet mds1 $LCTL get_param -n \
			 mdd.$(facet_svc mds1).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
	[ $repaired -eq 1 ] ||
	error "(6.1) Expect 1 fixed on mds1, but got: $repaired"

	if [ $MDSCOUNT -ge 2 ]; then
		repaired=$(do_facet mds2 $LCTL get_param -n \
			 mdd.$(facet_svc mds2).lfsck_layout |
				 awk '/^repaired_orphan/ { print $2 }')
		[ $repaired -eq 2 ] ||
		error "(6.2) Expect 2 fixed on mds2, but got: $repaired"
	fi

	$LFS path2fid $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS path2fid $DIR/$tdir/a2/f2
		$LFS getstripe $DIR/$tdir/a2/f2
	fi

	echo "The file size should be correct after layout LFSCK scanning"
	cur_size=$(ls -il $DIR/$tdir/a1/f1 | awk '{ print $6 }')
	[ "$cur_size" == "$saved_size" ] ||
		error "(7) Expect file1 size $saved_size, but got $cur_size"

	if [ $MDSCOUNT -ge 2 ]; then
		cur_size=$(ls -il $DIR/$tdir/a2/f2 | awk '{ print $6 }')
		[ "$cur_size" == "$saved_size" ] ||
		error "(8) Expect file2 size $saved_size, but got $cur_size"
	fi
}
run_test 18a "Find out orphan OST-object and repair it (1)"

test_18b() {
	echo "#####"
	echo "The target MDT-object is lost. The LFSCK should re-create the"
	echo "MDT-object under .lustre/lost+found/MDTxxxx. The admin should"
	echo "can move it back to normal namespace manually."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 -S 1M $DIR/$tdir/a1
	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=1M count=2
	local saved_size=$(ls -il $DIR/$tdir/a1/f1 | awk '{ print $6 }')
	local fid1=$($LFS path2fid $DIR/$tdir/a1/f1)
	echo ${fid1}
	$LFS getstripe $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS mkdir -i 1 $DIR/$tdir/a2
		$LFS setstripe -c 2 -i 1 -S 1M $DIR/$tdir/a2
		dd if=/dev/zero of=$DIR/$tdir/a2/f2 bs=1M count=2
		fid2=$($LFS path2fid $DIR/$tdir/a2/f2)
		echo ${fid2}
		$LFS getstripe $DIR/$tdir/a2/f2
	fi

	cancel_lru_locks osc

	echo "Inject failure, to simulate the case of missing the MDT-object"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ	0x1616
	do_facet mds1 $LCTL set_param fail_loc=0x1616
	rm -f $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0x1616
		rm -f $DIR/$tdir/a2/f2
	fi

	sync
	sleep 2

	do_facet mds1 $LCTL set_param fail_loc=0
	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0
	fi

	cancel_lru_locks mdc
	cancel_lru_locks osc

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o || error "(1) Fail to start LFSCK for layout!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" $LTIME ||
			error "(2) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		local cur_status=$(do_facet ost${k} $LCTL get_param -n \
				obdfilter.$(facet_svc ost${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(3) OST${k} Expect 'completed', but got '$cur_status'"
	done

	local repaired=$(do_facet mds1 $LCTL get_param -n \
			 mdd.$(facet_svc mds1).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
	[ $repaired -eq 1 ] ||
	error "(4.1) Expect 1 fixed on mds1, but got: $repaired"

	if [ $MDSCOUNT -ge 2 ]; then
		repaired=$(do_facet mds2 $LCTL get_param -n \
			 mdd.$(facet_svc mds2).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
		[ $repaired -eq 2 ] ||
		error "(4.2) Expect 2 fixed on mds2, but got: $repaired"
	fi

	echo "Move the files from ./lustre/lost+found/MDTxxxx to namespace"
	mv $MOUNT/.lustre/lost+found/MDT0000/${fid1}-R-0 $DIR/$tdir/a1/f1 ||
	error "(5) Fail to move $MOUNT/.lustre/lost+found/MDT0000/${fid1}-R-0"

	if [ $MDSCOUNT -ge 2 ]; then
		local name=$MOUNT/.lustre/lost+found/MDT0001/${fid2}-R-0
		mv $name $DIR/$tdir/a2/f2 || error "(6) Fail to move $name"
	fi

	$LFS path2fid $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS path2fid $DIR/$tdir/a2/f2
		$LFS getstripe $DIR/$tdir/a2/f2
	fi

	echo "The file size should be correct after layout LFSCK scanning"
	local cur_size=$(ls -il $DIR/$tdir/a1/f1 | awk '{ print $6 }')
	[ "$cur_size" == "$saved_size" ] ||
		error "(7) Expect file1 size $saved_size, but got $cur_size"

	if [ $MDSCOUNT -ge 2 ]; then
		cur_size=$(ls -il $DIR/$tdir/a2/f2 | awk '{ print $6 }')
		[ "$cur_size" == "$saved_size" ] ||
		error "(8) Expect file2 size $saved_size, but got $cur_size"
	fi
}
run_test 18b "Find out orphan OST-object and repair it (2)"

test_18c() {
	echo "#####"
	echo "The target MDT-object is lost, and the OST-object FID is missing."
	echo "The LFSCK should re-create the MDT-object with new FID under the "
	echo "directory .lustre/lost+found/MDTxxxx."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 -S 1M $DIR/$tdir/a1

	echo "Inject failure, to simulate the case of missing parent FID"
	#define OBD_FAIL_LFSCK_NOPFID		0x1617
	do_facet ost1 $LCTL set_param fail_loc=0x1617

	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=1M count=2
	$LFS getstripe $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS mkdir -i 1 $DIR/$tdir/a2
		$LFS setstripe -c 1 -i 0 -S 1M $DIR/$tdir/a2
		dd if=/dev/zero of=$DIR/$tdir/a2/f2 bs=1M count=2
		$LFS getstripe $DIR/$tdir/a2/f2
	fi

	cancel_lru_locks osc

	echo "Inject failure, to simulate the case of missing the MDT-object"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ	0x1616
	do_facet mds1 $LCTL set_param fail_loc=0x1616
	rm -f $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0x1616
		rm -f $DIR/$tdir/a2/f2
	fi

	sync
	sleep 2

	do_facet mds1 $LCTL set_param fail_loc=0
	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0
	fi

	cancel_lru_locks mdc
	cancel_lru_locks osc

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o || error "(1) Fail to start LFSCK for layout!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" $LTIME ||
			error "(2) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		local cur_status=$(do_facet ost${k} $LCTL get_param -n \
				obdfilter.$(facet_svc ost${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(3) OST${k} Expect 'completed', but got '$cur_status'"
	done

	if [ $MDSCOUNT -ge 2 ]; then
		expected=2
	else
		expected=1
	fi

	local repaired=$(do_facet mds1 $LCTL get_param -n \
			 mdd.$(facet_svc mds1).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
	[ $repaired -eq $expected ] ||
		error "(4) Expect $expected fixed on mds1, but got: $repaired"

	if [ $MDSCOUNT -ge 2 ]; then
		repaired=$(do_facet mds2 $LCTL get_param -n \
			   mdd.$(facet_svc mds2).lfsck_layout |
			   awk '/^repaired_orphan/ { print $2 }')
		[ $repaired -eq 0 ] ||
			error "(5) Expect 0 fixed on mds2, but got: $repaired"
	fi

	ls -ail $MOUNT/.lustre/lost+found/

	echo "There should NOT be some stub under .lustre/lost+found/MDT0001/"
	if [ -d $MOUNT/.lustre/lost+found/MDT0001 ]; then
		cname=$(find $MOUNT/.lustre/lost+found/MDT0001/ -name *-N-*)
		[ -z "$cname" ] ||
			error "(6) .lustre/lost+found/MDT0001/ should be empty"
	fi

	echo "There should be some stub under .lustre/lost+found/MDT0000/"
	[ -d $MOUNT/.lustre/lost+found/MDT0000 ] ||
		error "(7) $MOUNT/.lustre/lost+found/MDT0000/ should be there"

	cname=$(find $MOUNT/.lustre/lost+found/MDT0000/ -name *-N-*)
	[ ! -z "$cname" ] ||
		error "(8) .lustre/lost+found/MDT0000/ should not be empty"
}
run_test 18c "Find out orphan OST-object and repair it (3)"

test_18d() {
	echo "#####"
	echo "The target MDT-object layout EA slot is occpuied by some new"
	echo "created OST-object when repair dangling reference case. Such"
	echo "conflict OST-object has never been modified. Then when found"
	echo "the orphan OST-object, LFSCK will replace it with the orphan"
	echo "OST-object."
	echo "#####"

	check_mount_and_prep
	mkdir $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 -S 1M $DIR/$tdir/a1
	echo "guard" > $DIR/$tdir/a1/f1
	echo "foo" > $DIR/$tdir/a1/f2
	local saved_size=$(ls -il $DIR/$tdir/a1/f2 | awk '{ print $6 }')
	$LFS path2fid $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a1/f1
	$LFS path2fid $DIR/$tdir/a1/f2
	$LFS getstripe $DIR/$tdir/a1/f2
	cancel_lru_locks osc

	echo "Inject failure to make $DIR/$tdir/a1/f1 and $DIR/$tdir/a1/f2"
	echo "to reference the same OST-object (which is f1's OST-obejct)."
	echo "Then drop $DIR/$tdir/a1/f1 and its OST-object, so f2 becomes"
	echo "dangling reference case, but f2's old OST-object is there."
	echo

	#define OBD_FAIL_LFSCK_CHANGE_STRIPE	0x1618
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1618
	chown 1.1 $DIR/$tdir/a1/f2
	rm -f $DIR/$tdir/a1/f1
	sync
	sleep 2
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	echo "stopall to cleanup object cache"
	stopall > /dev/null
	echo "setupall"
	setupall > /dev/null

	echo "The file size should be incorrect since dangling referenced"
	local cur_size=$(ls -il $DIR/$tdir/a1/f2 | awk '{ print $6 }')
	[ "$cur_size" != "$saved_size" ] ||
		error "(1) Expect incorrect file2 size"

	#define OBD_FAIL_LFSCK_DELAY3		0x1602
	do_facet $SINGLEMDS $LCTL set_param fail_val=5 fail_loc=0x1602

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o -c || error "(2) Fail to start LFSCK for layout!"

	wait_update_facet mds1 "$LCTL get_param -n \
		mdd.$(facet_svc mds1).lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "scanning-phase2" $LTIME ||
		error "(3.0) MDS1 is not the expected 'scanning-phase2'"

	do_facet $SINGLEMDS $LCTL set_param fail_val=0 fail_loc=0

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" $LTIME ||
			error "(3) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		local cur_status=$(do_facet ost${k} $LCTL get_param -n \
				obdfilter.$(facet_svc ost${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(4) OST${k} Expect 'completed', but got '$cur_status'"
	done

	local repaired=$(do_facet $SINGLEMDS $LCTL get_param -n \
			 mdd.$(facet_svc $SINGLEMDS).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(5) Expect 1 orphan has been fixed, but got: $repaired"

	echo "The file size should be correct after layout LFSCK scanning"
	cur_size=$(ls -il $DIR/$tdir/a1/f2 | awk '{ print $6 }')
	[ "$cur_size" == "$saved_size" ] ||
		error "(6) Expect file2 size $saved_size, but got $cur_size"

	echo "The LFSCK should find back the original data."
	cat $DIR/$tdir/a1/f2
	$LFS path2fid $DIR/$tdir/a1/f2
	$LFS getstripe $DIR/$tdir/a1/f2
}
run_test 18d "Find out orphan OST-object and repair it (4)"

test_18e() {
	echo "#####"
	echo "The target MDT-object layout EA slot is occpuied by some new"
	echo "created OST-object when repair dangling reference case. Such"
	echo "conflict OST-object has been modified by others. To keep the"
	echo "new data, the LFSCK will create a new file to refernece this"
	echo "old orphan OST-object."
	echo "#####"

	check_mount_and_prep
	mkdir $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 -S 1M $DIR/$tdir/a1
	echo "guard" > $DIR/$tdir/a1/f1
	echo "foo" > $DIR/$tdir/a1/f2
	local saved_size=$(ls -il $DIR/$tdir/a1/f2 | awk '{ print $6 }')
	$LFS path2fid $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a1/f1
	$LFS path2fid $DIR/$tdir/a1/f2
	$LFS getstripe $DIR/$tdir/a1/f2
	cancel_lru_locks osc

	echo "Inject failure to make $DIR/$tdir/a1/f1 and $DIR/$tdir/a1/f2"
	echo "to reference the same OST-object (which is f1's OST-obejct)."
	echo "Then drop $DIR/$tdir/a1/f1 and its OST-object, so f2 becomes"
	echo "dangling reference case, but f2's old OST-object is there."
	echo

	#define OBD_FAIL_LFSCK_CHANGE_STRIPE	0x1618
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1618
	chown 1.1 $DIR/$tdir/a1/f2
	rm -f $DIR/$tdir/a1/f1
	sync
	sleep 2
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	echo "stopall to cleanup object cache"
	stopall > /dev/null
	echo "setupall"
	setupall > /dev/null

	echo "The file size should be incorrect since dangling referenced"
	local cur_size=$(ls -il $DIR/$tdir/a1/f2 | awk '{ print $6 }')
	[ "$cur_size" != "$saved_size" ] ||
		error "(1) Expect incorrect file2 size"

	#define OBD_FAIL_LFSCK_DELAY3		0x1602
	do_facet $SINGLEMDS $LCTL set_param fail_val=10 fail_loc=0x1602

	start_full_debug_logging

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o -c || error "(2) Fail to start LFSCK for layout!"

	wait_update_facet mds1 "$LCTL get_param -n \
		mdd.$(facet_svc mds1).lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "scanning-phase2" $LTIME ||
		error "(3) MDS1 is not the expected 'scanning-phase2'"

	# to guarantee all updates are synced.
	sync
	sleep 2

	echo "Write new data to f2 to modify the new created OST-object."
	echo "dummy" >> $DIR/$tdir/a1/f2

	do_facet $SINGLEMDS $LCTL set_param fail_val=0 fail_loc=0

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" $LTIME ||
			error "(4) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		local cur_status=$(do_facet ost${k} $LCTL get_param -n \
				obdfilter.$(facet_svc ost${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(5) OST${k} Expect 'completed', but got '$cur_status'"
	done

	stop_full_debug_logging

	local repaired=$(do_facet $SINGLEMDS $LCTL get_param -n \
			 mdd.$(facet_svc $SINGLEMDS).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(6) Expect 1 orphan has been fixed, but got: $repaired"

	echo "There should be stub file under .lustre/lost+found/MDT0000/"
	[ -d $MOUNT/.lustre/lost+found/MDT0000 ] ||
		error "(7) $MOUNT/.lustre/lost+found/MDT0000/ should be there"

	cname=$(find $MOUNT/.lustre/lost+found/MDT0000/ -name *-C-*)
	[ ! -z "$cname" ] ||
		error "(8) .lustre/lost+found/MDT0000/ should not be empty"

	echo "The stub file should keep the original f2 data"
	cur_size=$(ls -il $cname | awk '{ print $6 }')
	[ "$cur_size" == "$saved_size" ] ||
		error "(9) Expect file2 size $saved_size, but got $cur_size"

	cat $cname
	$LFS path2fid $cname
	$LFS getstripe $cname

	echo "The f2 should contains new data."
	cat $DIR/$tdir/a1/f2
	$LFS path2fid $DIR/$tdir/a1/f2
	$LFS getstripe $DIR/$tdir/a1/f2
}
run_test 18e "Find out orphan OST-object and repair it (5)"

test_18f() {
	[ $OSTCOUNT -lt 2 ] &&
		skip "The test needs at least 2 OSTs" && return

	echo "#####"
	echo "The target MDT-object is lost. The LFSCK should re-create the"
	echo "MDT-object under .lustre/lost+found/MDTxxxx. If some OST fail"
	echo "to verify some OST-object(s) during the first stage-scanning,"
	echo "the LFSCK should skip orphan OST-objects for such OST. Others"
	echo "should not be affected."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 -S 1M $DIR/$tdir/a1
	dd if=/dev/zero of=$DIR/$tdir/a1/guard bs=1M count=2
	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=1M count=2
	$LFS mkdir -i 0 $DIR/$tdir/a2
	$LFS setstripe -c 2 -i 0 -S 1M $DIR/$tdir/a2
	dd if=/dev/zero of=$DIR/$tdir/a2/f2 bs=1M count=2
	$LFS getstripe $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a2/f2

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS mkdir -i 1 $DIR/$tdir/a3
		$LFS setstripe -c 1 -i 0 -S 1M $DIR/$tdir/a3
		dd if=/dev/zero of=$DIR/$tdir/a3/guard bs=1M count=2
		dd if=/dev/zero of=$DIR/$tdir/a3/f3 bs=1M count=2
		$LFS mkdir -i 1 $DIR/$tdir/a4
		$LFS setstripe -c 2 -i 0 -S 1M $DIR/$tdir/a4
		dd if=/dev/zero of=$DIR/$tdir/a4/f4 bs=1M count=2
		$LFS getstripe $DIR/$tdir/a3/f3
		$LFS getstripe $DIR/$tdir/a4/f4
	fi

	cancel_lru_locks osc

	echo "Inject failure, to simulate the case of missing the MDT-object"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ	0x1616
	do_facet mds1 $LCTL set_param fail_loc=0x1616
	rm -f $DIR/$tdir/a1/f1
	rm -f $DIR/$tdir/a2/f2

	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0x1616
		rm -f $DIR/$tdir/a3/f3
		rm -f $DIR/$tdir/a4/f4
	fi

	sync
	sleep 2

	do_facet mds1 $LCTL set_param fail_loc=0
	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0
	fi

	cancel_lru_locks mdc
	cancel_lru_locks osc

	echo "Inject failure, to simulate the OST0 fail to handle"
	echo "MDT0 LFSCK request during the first-stage scanning."
	#define OBD_FAIL_LFSCK_BAD_NETWORK	0x161c
	do_facet mds1 $LCTL set_param fail_loc=0x161c fail_val=0

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o || error "(1) Fail to start LFSCK for layout!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "partial" $LTIME ||
			error "(2) MDS${k} is not the expected 'partial'"
	done

	wait_update_facet ost1 "$LCTL get_param -n \
		obdfilter.$(facet_svc ost1).lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "partial" $LTIME || {
		error "(3) OST1 is not the expected 'partial'"
	}

	wait_update_facet ost2 "$LCTL get_param -n \
		obdfilter.$(facet_svc ost2).lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" $LTIME || {
		error "(4) OST2 is not the expected 'completed'"
	}

	do_facet mds1 $LCTL set_param fail_loc=0 fail_val=0

	local repaired=$(do_facet mds1 $LCTL get_param -n \
			 mdd.$(facet_svc mds1).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(5) Expect 1 fixed on mds{1}, but got: $repaired"

	if [ $MDSCOUNT -ge 2 ]; then
		repaired=$(do_facet mds2 $LCTL get_param -n \
			 mdd.$(facet_svc mds2).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
		[ $repaired -eq 1 ] ||
		error "(6) Expect 1 fixed on mds{2}, but got: $repaired"
	fi

	echo "Trigger layout LFSCK on all devices again to cleanup"
	$START_LAYOUT -r -o || error "(7) Fail to start LFSCK for layout!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" $LTIME ||
			error "(8) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		cur_status=$(do_facet ost${k} $LCTL get_param -n \
			     obdfilter.$(facet_svc ost${k}).lfsck_layout |
			     awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(9) OST${k} Expect 'completed', but got '$cur_status'"

	done

	local repaired=$(do_facet mds1 $LCTL get_param -n \
			 mdd.$(facet_svc mds1).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
	[ $repaired -eq 2 ] ||
		error "(10) Expect 2 fixed on mds{1}, but got: $repaired"

	if [ $MDSCOUNT -ge 2 ]; then
		repaired=$(do_facet mds2 $LCTL get_param -n \
			 mdd.$(facet_svc mds2).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
		[ $repaired -eq 2 ] ||
		error "(11) Expect 2 fixed on mds{2}, but got: $repaired"
	fi
}
run_test 18f "Skip the failed OST(s) when handle orphan OST-objects"

$LCTL set_param debug=-cache > /dev/null

test_19a() {
	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	echo "foo" > $DIR/$tdir/a0
	echo "guard" > $DIR/$tdir/a1
	cancel_lru_locks osc

	echo "Inject failure, then client will offer wrong parent FID when read"
	do_facet ost1 $LCTL set_param -n \
		obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid 1
	#define OBD_FAIL_LFSCK_INVALID_PFID	0x1619
	$LCTL set_param fail_loc=0x1619

	echo "Read RPC with wrong parent FID should be denied"
	cat $DIR/$tdir/a0 && error "(3) Read should be denied!"
	$LCTL set_param fail_loc=0
}
run_test 19a "OST-object inconsistency self detect"

test_19b() {
	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	echo "Inject failure stub to make the OST-object to back point to"
	echo "non-exist MDT-object"

	#define OBD_FAIL_LFSCK_UNMATCHED_PAIR1	0x1611
	do_facet ost1 $LCTL set_param fail_loc=0x1611
	echo "foo" > $DIR/$tdir/f0
	cancel_lru_locks osc
	do_facet ost1 $LCTL set_param fail_loc=0

	echo "Nothing should be fixed since self detect and repair is disabled"
	local repaired=$(do_facet ost1 $LCTL get_param -n \
			obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid |
			awk '/^repaired/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(1) Expected 0 repaired, but got $repaired"

	echo "Read RPC with right parent FID should be accepted,"
	echo "and cause parent FID on OST to be fixed"

	do_facet ost1 $LCTL set_param -n \
		obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid 1
	cat $DIR/$tdir/f0 || error "(2) Read should not be denied!"

	repaired=$(do_facet ost1 $LCTL get_param -n \
		obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid |
		awk '/^repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(3) Expected 1 repaired, but got $repaired"
}
run_test 19b "OST-object inconsistency self repair"

test_20() {
	[ $OSTCOUNT -lt 2 ] &&
		skip "The test needs at least 2 OSTs" && return

	echo "#####"
	echo "The target MDT-object and some of its OST-object are lost."
	echo "The LFSCK should find out the left OST-objects and re-create"
	echo "the MDT-object under the direcotry .lustre/lost+found/MDTxxxx/"
	echo "with the partial OST-objects (LOV EA hole)."

	echo "New client can access the file with LOV EA hole via normal"
	echo "system tools or commands without crash the system."

	echo "For old client, even though it cannot access the file with"
	echo "LOV EA hole, it should not cause the system crash."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/a1
	if [ $OSTCOUNT -gt 2 ]; then
		$LFS setstripe -c 3 -i 0 -S 1M $DIR/$tdir/a1
		bcount=513
	else
		$LFS setstripe -c 2 -i 0 -S 1M $DIR/$tdir/a1
		bcount=257
	fi

	# 256 blocks on the stripe0.
	# 1 block on the stripe1 for 2 OSTs case.
	# 256 blocks on the stripe1 for other cases.
	# 1 block on the stripe2 if OSTs > 2
	dd if=/dev/zero of=$DIR/$tdir/a1/f0 bs=4096 count=$bcount
	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=4096 count=$bcount
	dd if=/dev/zero of=$DIR/$tdir/a1/f2 bs=4096 count=$bcount

	local fid0=$($LFS path2fid $DIR/$tdir/a1/f0)
	local fid1=$($LFS path2fid $DIR/$tdir/a1/f1)
	local fid2=$($LFS path2fid $DIR/$tdir/a1/f2)

	echo ${fid0}
	$LFS getstripe $DIR/$tdir/a1/f0
	echo ${fid1}
	$LFS getstripe $DIR/$tdir/a1/f1
	echo ${fid2}
	$LFS getstripe $DIR/$tdir/a1/f2

	if [ $OSTCOUNT -gt 2 ]; then
		dd if=/dev/zero of=$DIR/$tdir/a1/f3 bs=4096 count=$bcount
		fid3=$($LFS path2fid $DIR/$tdir/a1/f3)
		echo ${fid3}
		$LFS getstripe $DIR/$tdir/a1/f3
	fi

	cancel_lru_locks osc

	echo "Inject failure..."
	echo "To simulate f0 lost MDT-object"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ	0x1616
	do_facet mds1 $LCTL set_param fail_loc=0x1616
	rm -f $DIR/$tdir/a1/f0

	echo "To simulate f1 lost MDT-object and OST-object0"
	#define OBD_FAIL_LFSCK_LOST_SPEOBJ	0x161a
	do_facet mds1 $LCTL set_param fail_loc=0x161a
	rm -f $DIR/$tdir/a1/f1

	echo "To simulate f2 lost MDT-object and OST-object1"
	do_facet mds1 $LCTL set_param fail_val=1
	rm -f $DIR/$tdir/a1/f2

	if [ $OSTCOUNT -gt 2 ]; then
		echo "To simulate f3 lost MDT-object and OST-object2"
		do_facet mds1 $LCTL set_param fail_val=2
		rm -f $DIR/$tdir/a1/f3
	fi

	umount_client $MOUNT
	sync
	sleep 2
	do_facet mds1 $LCTL set_param fail_loc=0 fail_val=0

	echo "Inject failure to slow down the LFSCK on OST0"
	#define OBD_FAIL_LFSCK_DELAY5		0x161b
	do_facet ost1 $LCTL set_param fail_loc=0x161b

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o || error "(1) Fail to start LFSCK for layout!"

	sleep 3
	do_facet ost1 $LCTL set_param fail_loc=0

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" 32 ||
			error "(2) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		local cur_status=$(do_facet ost${k} $LCTL get_param -n \
				obdfilter.$(facet_svc ost${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(3) OST${k} Expect 'completed', but got '$cur_status'"
	done

	local repaired=$(do_facet mds1 $LCTL get_param -n \
			 mdd.$(facet_svc mds1).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
	if [ $OSTCOUNT -gt 2 ]; then
		[ $repaired -eq 9 ] ||
			error "(4.1) Expect 9 fixed on mds1, but got: $repaired"
	else
		[ $repaired -eq 4 ] ||
			error "(4.2) Expect 4 fixed on mds1, but got: $repaired"
	fi

	mount_client $MOUNT || error "(5.0) Fail to start client!"

	LOV_PATTERN_F_HOLE=0x40000000

	#
	# ${fid0}-R-0 is the old f0
	#
	local name="$MOUNT/.lustre/lost+found/MDT0000/${fid0}-R-0"
	echo "Check $name, which is the old f0"

	$LFS getstripe -v $name || error "(5.1) cannot getstripe on $name"

	local pattern=0x$($LFS getstripe -L $name)
	[[ $((pattern & LOV_PATTERN_F_HOLE)) -eq 0 ]] ||
		error "(5.2) NOT expect pattern flag hole, but got $pattern"

	local stripes=$($LFS getstripe -c $name)
	if [ $OSTCOUNT -gt 2 ]; then
		[ $stripes -eq 3 ] ||
		error "(5.3.1) expect the stripe count is 3, but got $stripes"
	else
		[ $stripes -eq 2 ] ||
		error "(5.3.2) expect the stripe count is 2, but got $stripes"
	fi

	local size=$(stat $name | awk '/Size:/ { print $2 }')
	[ $size -eq $((4096 * $bcount)) ] ||
		error "(5.4) expect the size $((4096 * $bcount)), but got $size"

	cat $name > /dev/null || error "(5.5) cannot read $name"

	echo "dummy" >> $name || error "(5.6) cannot write $name"

	chown $RUNAS_ID:$RUNAS_GID $name || error "(5.7) cannot chown on $name"

	touch $name || error "(5.8) cannot touch $name"

	rm -f $name || error "(5.9) cannot unlink $name"

	#
	# ${fid1}-R-0 contains the old f1's stripe1 (and stripe2 if OSTs > 2)
	#
	name="$MOUNT/.lustre/lost+found/MDT0000/${fid1}-R-0"
	if [ $OSTCOUNT -gt 2 ]; then
		echo "Check $name, it contains the old f1's stripe1 and stripe2"
	else
		echo "Check $name, it contains the old f1's stripe1"
	fi

	$LFS getstripe -v $name || error "(6.1) cannot getstripe on $name"

	pattern=0x$($LFS getstripe -L $name)
	[[ $((pattern & LOV_PATTERN_F_HOLE)) -ne 0 ]] ||
		error "(6.2) expect pattern flag hole, but got $pattern"

	stripes=$($LFS getstripe -c $name)
	if [ $OSTCOUNT -gt 2 ]; then
		[ $stripes -eq 3 ] ||
		error "(6.3.1) expect the stripe count is 3, but got $stripes"
	else
		[ $stripes -eq 2 ] ||
		error "(6.3.2) expect the stripe count is 2, but got $stripes"
	fi

	size=$(stat $name | awk '/Size:/ { print $2 }')
	[ $size -eq $((4096 * $bcount)) ] ||
		error "(6.4) expect the size $((4096 * $bcount)), but got $size"

	cat $name > /dev/null && error "(6.5) normal read $name should fail"

	local failures=$(dd if=$name of=$DIR/$tdir/dump conv=sync,noerror \
			 bs=4096 2>&1 | grep "Input/output error" | wc -l)

	# stripe0 is dummy
	[ $failures -eq 256 ] ||
		error "(6.6) expect 256 IO failures, but get $failures"

	size=$(stat $DIR/$tdir/dump | awk '/Size:/ { print $2 }')
	[ $size -eq $((4096 * $bcount)) ] ||
		error "(6.7) expect the size $((4096 * $bcount)), but got $size"

	dd if=/dev/zero of=$name conv=sync,notrunc bs=4096 count=1 &&
		error "(6.8) write to the LOV EA hole should fail"

	dd if=/dev/zero of=$name conv=sync,notrunc bs=4096 count=1 seek=300 ||
		error "(6.9) write to normal stripe should NOT fail"

	echo "foo" >> $name && error "(6.10) append write $name should fail"

	chown $RUNAS_ID:$RUNAS_GID $name || error "(6.11) cannot chown on $name"

	touch $name || error "(6.12) cannot touch $name"

	rm -f $name || error "(6.13) cannot unlink $name"

	#
	# ${fid2}-R-0 it contains the old f2's stripe0 (and stripe2 if OSTs > 2)
	#
	name="$MOUNT/.lustre/lost+found/MDT0000/${fid2}-R-0"
	if [ $OSTCOUNT -gt 2 ]; then
		echo "Check $name, it contains the old f2's stripe0 and stripe2"
	else
		echo "Check $name, it contains the old f2's stripe0"
	fi

	$LFS getstripe -v $name || error "(7.1) cannot getstripe on $name"

	pattern=0x$($LFS getstripe -L $name)
	stripes=$($LFS getstripe -c $name)
	size=$(stat $name | awk '/Size:/ { print $2 }')
	if [ $OSTCOUNT -gt 2 ]; then
		[[ $((pattern & LOV_PATTERN_F_HOLE)) -ne 0 ]] ||
		error "(7.2.1) expect pattern flag hole, but got $pattern"

		[ $stripes -eq 3 ] ||
		error "(7.3.1) expect the stripe count is 3, but got $stripes"

		[ $size -eq $((4096 * $bcount)) ] ||
		error "(7.4.1) expect size $((4096 * $bcount)), but got $size"

		cat $name > /dev/null &&
			error "(7.5.1) normal read $name should fail"

		failures=$(dd if=$name of=$DIR/$tdir/dump conv=sync,noerror \
			   bs=4096 2>&1 | grep "Input/output error" | wc -l)
		# stripe1 is dummy
		[ $failures -eq 256 ] ||
			error "(7.6) expect 256 IO failures, but get $failures"

		size=$(stat $DIR/$tdir/dump | awk '/Size:/ { print $2 }')
		[ $size -eq $((4096 * $bcount)) ] ||
		error "(7.7) expect the size $((4096 * $bcount)), but got $size"

		dd if=/dev/zero of=$name conv=sync,notrunc bs=4096 count=1 \
		seek=300 && error "(7.8.0) write to the LOV EA hole should fail"

		dd if=/dev/zero of=$name conv=sync,notrunc bs=4096 count=1 ||
		error "(7.8.1) write to normal stripe should NOT fail"

		echo "foo" >> $name &&
			error "(7.8.3) append write $name should fail"

		chown $RUNAS_ID:$RUNAS_GID $name ||
			error "(7.9.1) cannot chown on $name"

		touch $name || error "(7.10.1) cannot touch $name"
	else
		[[ $((pattern & LOV_PATTERN_F_HOLE)) -eq 0 ]] ||
		error "(7.2.2) NOT expect pattern flag hole, but got $pattern"

		[ $stripes -eq 1 ] ||
		error "(7.3.2) expect the stripe count is 1, but got $stripes"

		# stripe1 is dummy
		[ $size -eq $((4096 * (256 + 0))) ] ||
		error "(7.4.2) expect the size $((4096 * 256)), but got $size"

		cat $name > /dev/null || error "(7.5.2) cannot read $name"

		echo "dummy" >> $name || error "(7.8.2) cannot write $name"

		chown $RUNAS_ID:$RUNAS_GID $name ||
			error "(7.9.2) cannot chown on $name"

		touch $name || error "(7.10.2) cannot touch $name"
	fi

	rm -f $name || error "(7.11) cannot unlink $name"

	[ $OSTCOUNT -le 2 ] && return

	#
	# ${fid3}-R-0 should contains the old f3's stripe0 and stripe1
	#
	name="$MOUNT/.lustre/lost+found/MDT0000/${fid3}-R-0"
	echo "Check $name, which contains the old f3's stripe0 and stripe1"

	$LFS getstripe -v $name || error "(8.1) cannot getstripe on $name"

	pattern=0x$($LFS getstripe -L $name)
	[[ $((pattern & LOV_PATTERN_F_HOLE)) -eq 0 ]] ||
		error "(8.2) NOT expect pattern flag hole, but got $pattern"

	stripes=$($LFS getstripe -c $name)
	# LFSCK does not know the old f3 had 3 stripes.
	# It only tries to find as much as possible.
	# The stripe count depends on the last stripe's offset.
	[ $stripes -eq 2 ] ||
		error "(8.3) expect the stripe count is 2, but got $stripes"

	size=$(stat $name | awk '/Size:/ { print $2 }')
	# stripe2 is lost
	[ $size -eq $((4096 * (256 + 256 + 0))) ] ||
		error "(8.4) expect the size $((4096 * 512)), but got $size"

	cat $name > /dev/null || error "(8.5) cannot read $name"

	echo "dummy" >> $name || error "(8.6) cannot write $name"

	chown $RUNAS_ID:$RUNAS_GID $name ||
		error "(8.7) cannot chown on $name"

	touch $name || error "(8.8) cannot touch $name"

	rm -f $name || error "(8.9) cannot unlink $name"
}
run_test 20 "Handle the orphan with dummy LOV EA slot properly"

test_21() {
	[[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.5.59) ]] &&
		skip "ignore the test if MDS is older than 2.5.59" && return

	check_mount_and_prep
	createmany -o $DIR/$tdir/f 100 || error "(0) Fail to create 100 files"

	echo "Start all LFSCK components by default (-s 1)"
	do_facet mds1 $LCTL lfsck_start -M ${FSNAME}-MDT0000 -s 1 -r ||
		error "Fail to start LFSCK"

	echo "namespace LFSCK should be in 'scanning-phase1' status"
	local STATUS=$($SHOW_NAMESPACE | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "Expect namespace 'scanning-phase1', but got '$STATUS'"

	echo "layout LFSCK should be in 'scanning-phase1' status"
	STATUS=$($SHOW_LAYOUT | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "Expect layout 'scanning-phase1', but got '$STATUS'"

	echo "Stop all LFSCK components by default"
	do_facet mds1 $LCTL lfsck_stop -M ${FSNAME}-MDT0000 ||
		error "Fail to stop LFSCK"
}
run_test 21 "run all LFSCK components by default"

test_22a() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "We need at least 2 MDSes for this test" && return

	echo "#####"
	echo "The parent_A references the child directory via some name entry,"
	echo "but the child directory back references another parent_B via its"
	echo "".." name entry. The parent_B does not exist. Then the namespace"
	echo "LFSCK will repair the child directory's ".." name entry."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 1 $DIR/$tdir/guard || error "(1) Fail to mkdir on MDT1"
	$LFS mkdir -i 1 $DIR/$tdir/foo || error "(2) Fail to mkdir on MDT1"

	echo "Inject failure stub on MDT0 to simulate bad dotdot name entry"
	echo "The dummy's dotdot name entry references the guard."
	#define OBD_FAIL_LFSCK_BAD_PARENT	0x161e
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x161e
	$LFS mkdir -i 0 $DIR/$tdir/foo/dummy ||
		error "(3) Fail to mkdir on MDT0"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	rmdir $DIR/$tdir/guard || error "(4) Fail to rmdir $DIR/$tdir/guard"

	echo "Trigger namespace LFSCK to repair unmatched pairs"
	$START_NAMESPACE -A -r ||
		error "(5) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(6) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^unmatched_pairs_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(7) Fail to repair unmatched pairs: $repaired"

	echo "'ls' should success after namespace LFSCK repairing"
	ls -ail $DIR/$tdir/foo/dummy > /dev/null ||
		error "(8) ls should success."
}
run_test 22a "LFSCK can repair unmatched pairs (1)"

test_22b() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "We need at least 2 MDSes for this test" && return

	echo "#####"
	echo "The parent_A references the child directory via the name entry_B,"
	echo "but the child directory back references another parent_C via its"
	echo "".." name entry. The parent_C exists, but there is no the name"
	echo "entry_B under the parent_C. Then the namespace LFSCK will repair"
	echo "the child directory's ".." name entry and its linkEA."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 1 $DIR/$tdir/guard || error "(1) Fail to mkdir on MDT1"
	$LFS mkdir -i 1 $DIR/$tdir/foo || error "(2) Fail to mkdir on MDT1"

	echo "Inject failure stub on MDT0 to simulate bad dotdot name entry"
	echo "and bad linkEA. The dummy's dotdot name entry references the"
	echo "guard. The dummy's linkEA references n non-exist name entry."
	#define OBD_FAIL_LFSCK_BAD_PARENT	0x161e
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x161e
	$LFS mkdir -i 0 $DIR/$tdir/foo/dummy ||
		error "(3) Fail to mkdir on MDT0"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	local dummyfid=$($LFS path2fid $DIR/$tdir/foo/dummy)
	echo "fid2path should NOT work on the dummy's FID $dummyfid"
	local dummyname=$($LFS fid2path $DIR $dummyfid)
	[ "$dummyname" != "$DIR/$tdir/foo/dummy" ] ||
		error "(4) fid2path works unexpectedly."

	echo "Trigger namespace LFSCK to repair unmatched pairs"
	$START_NAMESPACE -A -r ||
		error "(5) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(6) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^unmatched_pairs_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(7) Fail to repair unmatched pairs: $repaired"

	echo "fid2path should work on the dummy's FID $dummyfid after LFSCK"
	local dummyname=$($LFS fid2path $DIR $dummyfid)
	[ "$dummyname" == "$DIR/$tdir/foo/dummy" ] ||
		error "(8) fid2path does not work"
}
run_test 22b "LFSCK can repair unmatched pairs (2)"

test_23a() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "We need at least 2 MDSes for this test" && return

	echo "#####"
	echo "The name entry is there, but the MDT-object for such name "
	echo "entry does not exist. The namespace LFSCK should find out "
	echo "and repair the inconsistency as required."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0 on MDT0"
	$LFS mkdir -i 1 $DIR/$tdir/d0/d1 || error "(2) Fail to mkdir d1 on MDT1"

	echo "Inject failure stub on MDT1 to simulate dangling name entry"
	#define OBD_FAIL_LFSCK_DANGLING2	0x1620
	do_facet mds2 $LCTL set_param fail_loc=0x1620
	rmdir $DIR/$tdir/d0/d1 || error "(3) Fail to rmdir d1"
	do_facet mds2 $LCTL set_param fail_loc=0

	echo "'ls' should fail because of dangling name entry"
	ls -ail $DIR/$tdir/d0/d1 > /dev/null 2>&1 && error "(4) ls should fail."

	echo "Trigger namespace LFSCK to find out dangling name entry"
	$START_NAMESPACE -A -r ||
		error "(5) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(6) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^dangling_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(7) Fail to repair dangling name entry: $repaired"

	echo "'ls' should fail because not re-create MDT-object by default"
	ls -ail $DIR/$tdir/d0/d1 > /dev/null 2>&1 && error "(8) ls should fail."

	echo "Trigger namespace LFSCK again to repair dangling name entry"
	$START_NAMESPACE -A -r -C ||
		error "(9) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(10) unexpected status"
	}

	repaired=$($SHOW_NAMESPACE |
		   awk '/^dangling_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(11) Fail to repair dangling name entry: $repaired"

	echo "'ls' should success after namespace LFSCK repairing"
	ls -ail $DIR/$tdir/d0/d1 > /dev/null || error "(12) ls should success."
}
run_test 23a "LFSCK can repair dangling name entry (1)"

test_23b() {
	echo "#####"
	echo "The objectA has multiple hard links, one of them corresponding"
	echo "to the name entry_B. But there is something wrong for the name"
	echo "entry_B and cause entry_B to references non-exist object_C."
	echo "In the first-stage scanning, the LFSCK will think the entry_B"
	echo "as dangling, and re-create the lost object_C. When the LFSCK"
	echo "comes to the second-stage scanning, it will find that the"
	echo "former re-creating object_C is not proper, and will try to"
	echo "replace the object_C with the real object_A."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0 on MDT0"
	echo "dummy" > $DIR/$tdir/d0/f0 || error "(2) Fail to touch on MDT0"
	echo "dead" > $DIR/$tdir/d0/f1 || error "(3) Fail to touch on MDT0"

	echo "Inject failure stub on MDT0 to simulate dangling name entry"
	#define OBD_FAIL_LFSCK_DANGLING3	0x1621
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1621
	ln $DIR/$tdir/d0/f0 $DIR/$tdir/d0/foo || error "(4) Fail to hard link"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	rm -f $DIR/$tdir/d0/f1 || error "(5) Fail to unlink $DIR/$tdir/d0/f1"

	echo "'ls' should fail because of dangling name entry"
	ls -ail $DIR/$tdir/d0/foo > /dev/null 2>&1 &&
		error "(6) ls should fail."

	echo "Trigger namespace LFSCK to find out dangling name entry"
	$START_NAMESPACE -r -C ||
		error "(7) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(8) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^dangling_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(9) Fail to repair dangling name entry: $repaired"

	repaired=$($SHOW_NAMESPACE |
		   awk '/^multiple_linked_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(10) Fail to drop the former created object: $repaired"

	local data=$(cat $DIR/$tdir/d0/foo)
	[ "$data" == "dummy" ] ||
		error "(11) The $DIR/$tdir/d0/foo is not recovered: $data"
}
run_test 23b "LFSCK can repair dangling name entry (2)"

test_23c() {
	echo "#####"
	echo "The objectA has multiple hard links, one of them corresponding"
	echo "to the name entry_B. But there is something wrong for the name"
	echo "entry_B and cause entry_B to references non-exist object_C."
	echo "In the first-stage scanning, the LFSCK will think the entry_B"
	echo "as dangling, and re-create the lost object_C. And then others"
	echo "modified the re-created object_C. When the LFSCK comes to the"
	echo "second-stage scanning, it will find that the former re-creating"
	echo "object_C maybe wrong and try to replace the object_C with the"
	echo "real object_A. But because object_C has been modified, so the"
	echo "LFSCK cannot replace it."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0 on MDT0"
	echo "dummy" > $DIR/$tdir/d0/f0 || error "(2) Fail to touch on MDT0"
	echo "dead" > $DIR/$tdir/d0/f1 || error "(3) Fail to touch on MDT0"

	echo "Inject failure stub on MDT0 to simulate dangling name entry"
	#define OBD_FAIL_LFSCK_DANGLING3	0x1621
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1621
	ln $DIR/$tdir/d0/f0 $DIR/$tdir/d0/foo || error "(4) Fail to hard link"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	rm -f $DIR/$tdir/d0/f1 || error "(5) Fail to unlink $DIR/$tdir/d0/f1"

	echo "'ls' should fail because of dangling name entry"
	ls -ail $DIR/$tdir/d0/foo > /dev/null 2>&1 &&
		error "(6) ls should fail."

	#define OBD_FAIL_LFSCK_DELAY3		0x1602
	do_facet $SINGLEMDS $LCTL set_param fail_val=10 fail_loc=0x1602

	echo "Trigger namespace LFSCK to find out dangling name entry"
	$START_NAMESPACE -r -C ||
		error "(7) Fail to start LFSCK for namespace"

	wait_update_facet client "stat $DIR/$tdir/d0/foo |
		awk '/Size/ { print \\\$2 }'" "0" 32 || {
		stat $DIR/$tdir/guard
		$SHOW_NAMESPACE
		error "(8) unexpected size"
	}

	echo "data" >> $DIR/$tdir/d0/foo || error "(9) Fail to write"
	cancel_lru_locks osc

	do_facet $SINGLEMDS $LCTL set_param fail_val=0 fail_loc=0
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(10) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^dangling_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(11) Fail to repair dangling name entry: $repaired"

	local data=$(cat $DIR/$tdir/d0/foo)
	[ "$data" != "dummy" ] ||
		error "(12) The $DIR/$tdir/d0/foo should not be recovered"
}
run_test 23c "LFSCK can repair dangling name entry (3)"

test_24() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "We need at least 2 MDSes for this test" && return

	echo "#####"
	echo "Two MDT-objects back reference the same name entry via their"
	echo "each own linkEA entry, but the name entry only references one"
	echo "MDT-object. The namespace LFSCK will remove the linkEA entry"
	echo "for the MDT-object that is not recognized. If such MDT-object"
	echo "has no other linkEA entry after the removing, then the LFSCK"
	echo "will add it as orphan under the .lustre/lost+found/MDTxxxx/."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 1 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0"

	mkdir $DIR/$tdir/d0/guard || error "(1) Fail to mkdir guard"
	$LFS path2fid $DIR/$tdir/d0/guard

	mkdir $DIR/$tdir/d0/dummy || error "(2) Fail to mkdir dummy"
	$LFS path2fid $DIR/$tdir/d0/dummy

	local pfid
	if [ $(facet_fstype $SINGLEMDS) != ldiskfs ]; then
		pfid=$($LFS path2fid $DIR/$tdir/d0/guard)
	else
		pfid=$($LFS path2fid $DIR/$tdir/d0/dummy)
	fi

	touch $DIR/$tdir/d0/guard/foo ||
		error "(3) Fail to touch $DIR/$tdir/d0/guard/foo"

	echo "Inject failure stub on MDT0 to simulate the case that"
	echo "the $DIR/$tdir/d0/dummy/foo has the 'bad' linkEA entry"
	echo "that references $DIR/$tdir/d0/guard/foo."
	echo "Then remove the name entry $DIR/$tdir/d0/dummy/foo."
	echo "So the MDT-object $DIR/$tdir/d0/dummy/foo will be left"
	echo "there with the same linkEA entry as another MDT-object"
	echo "$DIR/$tdir/d0/guard/foo has"

	#define OBD_FAIL_LFSCK_MUL_REF		0x1622
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1622
	$LFS mkdir -i 0 $DIR/$tdir/d0/dummy/foo ||
		error "(4) Fail to mkdir $DIR/$tdir/d0/dummy/foo"
	$LFS path2fid $DIR/$tdir/d0/dummy/foo
	local cfid=$($LFS path2fid $DIR/$tdir/d0/dummy/foo)
	rmdir $DIR/$tdir/d0/dummy/foo ||
		error "(5) Fail to remove $DIR/$tdir/d0/dummy/foo name entry"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	echo "stat $DIR/$tdir/d0/dummy/foo should fail"
	stat $DIR/$tdir/d0/dummy/foo > /dev/null 2>&1 &&
		error "(6) stat successfully unexpectedly"

	echo "Trigger namespace LFSCK to repair multiple-referenced name entry"
	$START_NAMESPACE -A -r ||
		error "(7) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(8) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^multiple_referenced_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
	error "(9) Fail to repair multiple referenced name entry: $repaired"

	echo "There should be an orphan under .lustre/lost+found/MDT0000/"
	[ -d $MOUNT/.lustre/lost+found/MDT0000 ] ||
		error "(10) $MOUNT/.lustre/lost+found/MDT0000/ should be there"

	local cname="$cfid-$pfid-D-0"
	ls -ail $MOUNT/.lustre/lost+found/MDT0000/$cname ||
		error "(11) .lustre/lost+found/MDT0000/ should not be empty"
}
run_test 24 "LFSCK can repair multiple-referenced name entry"

test_25() {
	[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
		skip "Only support to inject failure on ldiskfs" && return

	echo "#####"
	echo "The file type in the name entry does not match the file type"
	echo "claimed by the referenced object. Then the LFSCK will update"
	echo "the file type in the name entry."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0"

	echo "Inject failure stub on MDT0 to simulate the case that"
	echo "the file type stored in the name entry is wrong."

	#define OBD_FAIL_LFSCK_BAD_TYPE		0x1623
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1623
	touch $DIR/$tdir/d0/foo || error "(2) Fail to touch $DIR/$tdir/d0/foo"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	echo "Trigger namespace LFSCK to repair bad file type in the name entry"
	$START_NAMESPACE -r || error "(3) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^bad_file_type_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
	error "(5) Fail to repair bad file type in name entry: $repaired"

	ls -ail $DIR/$tdir/d0 || error "(6) Fail to 'ls' the $DIR/$tdir/d0"
}
run_test 25 "LFSCK can repair bad file type in the name entry"

test_26a() {
	echo "#####"
	echo "The local name entry back referenced by the MDT-object is lost."
	echo "The namespace LFSCK will add the missing local name entry back"
	echo "to the normal namespace."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0"
	touch $DIR/$tdir/d0/foo || error "(2) Fail to create foo"
	local foofid=$($LFS path2fid $DIR/$tdir/d0/foo)

	ln $DIR/$tdir/d0/foo $DIR/$tdir/d0/dummy ||
		error "(3) Fail to hard link to $DIR/$tdir/d0/foo"

	echo "Inject failure stub on MDT0 to simulate the case that"
	echo "foo's name entry will be removed, but the foo's object"
	echo "and its linkEA are kept in the system."

	#define OBD_FAIL_LFSCK_NO_NAMEENTRY	0x1624
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1624
	rm -f $DIR/$tdir/d0/foo || error "(4) Fail to unlink $DIR/$tdir/d0/foo"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	ls -ail $DIR/$tdir/d0/foo > /dev/null 2>&1 && "(5) 'ls' should fail"

	echo "Trigger namespace LFSCK to repair the missing remote name entry"
	$START_NAMESPACE -r -A ||
		error "(6) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(7) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^lost_dirent_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(8) Fail to repair lost dirent: $repaired"

	ls -ail $DIR/$tdir/d0/foo ||
		error "(9) Fail to 'ls' $DIR/$tdir/d0/foo"

	local foofid2=$($LFS path2fid $DIR/$tdir/d0/foo)
	[ "$foofid" == "$foofid2" ] ||
		error "(10) foo's FID changed: $foofid, $foofid2"
}
run_test 26a "LFSCK can add the missing local name entry back to the namespace"

test_26b() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "We need at least 2 MDSes for this test" && return

	echo "#####"
	echo "The remote name entry back referenced by the MDT-object is lost."
	echo "The namespace LFSCK will add the missing remote name entry back"
	echo "to the normal namespace."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 1 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0"
	$LFS mkdir -i 0 $DIR/$tdir/d0/foo || error "(2) Fail to mkdir foo"
	local foofid=$($LFS path2fid $DIR/$tdir/d0/foo)

	echo "Inject failure stub on MDT0 to simulate the case that"
	echo "foo's name entry will be removed, but the foo's object"
	echo "and its linkEA are kept in the system."

	#define OBD_FAIL_LFSCK_NO_NAMEENTRY	0x1624
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1624
	rmdir $DIR/$tdir/d0/foo || error "(3) Fail to rmdir $DIR/$tdir/d0/foo"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	ls -ail $DIR/$tdir/d0/foo > /dev/null 2>&1 && "(4) 'ls' should fail"

	echo "Trigger namespace LFSCK to repair the missing remote name entry"
	$START_NAMESPACE -r -A ||
		error "(5) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(6) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^lost_dirent_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(7) Fail to repair lost dirent: $repaired"

	ls -ail $DIR/$tdir/d0/foo ||
		error "(8) Fail to 'ls' $DIR/$tdir/d0/foo"

	local foofid2=$($LFS path2fid $DIR/$tdir/d0/foo)
	[ "$foofid" == "$foofid2" ] ||
		error "(9) foo's FID changed: $foofid, $foofid2"
}
run_test 26b "LFSCK can add the missing remote name entry back to the namespace"

test_27a() {
	echo "#####"
	echo "The local parent referenced by the MDT-object linkEA is lost."
	echo "The namespace LFSCK will re-create the lost parent as orphan."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0"
	touch $DIR/$tdir/d0/foo || error "(2) Fail to create foo"
	ln $DIR/$tdir/d0/foo $DIR/$tdir/d0/dummy ||
		error "(3) Fail to hard link to $DIR/$tdir/d0/foo"

	echo "Inject failure stub on MDT0 to simulate the case that"
	echo "foo's name entry will be removed, but the foo's object"
	echo "and its linkEA are kept in the system. And then remove"
	echo "another hard link and the parent directory."

	#define OBD_FAIL_LFSCK_NO_NAMEENTRY	0x1624
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1624
	rm -f $DIR/$tdir/d0/foo ||
		error "(4) Fail to unlink $DIR/$tdir/d0/foo"
	rm -f $DIR/$tdir/d0/dummy ||
		error "(5) Fail to unlink $DIR/$tdir/d0/dummy"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	rm -rf $DIR/$tdir/d0 || error "(5) Fail to unlink the dir d0"
	ls -ail $DIR/$tdir/d0 > /dev/null 2>&1 && "(6) 'ls' should fail"

	echo "Trigger namespace LFSCK to repair the lost parent"
	$START_NAMESPACE -r -A ||
		error "(6) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(7) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^lost_dirent_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(8) Fail to repair lost dirent: $repaired"

	echo "There should be an orphan under .lustre/lost+found/MDT0000/"
	[ -d $MOUNT/.lustre/lost+found/MDT0000 ] ||
		error "(9) $MOUNT/.lustre/lost+found/MDT0000/ should be there"

	ls -ail $MOUNT/.lustre/lost+found/MDT0000/

	cname=$(find $MOUNT/.lustre/lost+found/MDT0000/ -name *-P-*)
	[ ! -z "$cname" ] ||
		error "(10) .lustre/lost+found/MDT0000/ should not be empty"
}
run_test 27a "LFSCK can recreate the lost local parent directory as orphan"

test_27b() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "We need at least 2 MDSes for this test" && return

	echo "#####"
	echo "The remote parent referenced by the MDT-object linkEA is lost."
	echo "The namespace LFSCK will re-create the lost parent as orphan."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 1 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0"
	$LFS mkdir -i 0 $DIR/$tdir/d0/foo || error "(2) Fail to mkdir foo"

	$LFS path2fid $DIR/$tdir/d0

	echo "Inject failure stub on MDT0 to simulate the case that"
	echo "foo's name entry will be removed, but the foo's object"
	echo "and its linkEA are kept in the system. And then remove"
	echo "the parent directory."

	#define OBD_FAIL_LFSCK_NO_NAMEENTRY	0x1624
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1624
	rmdir $DIR/$tdir/d0/foo || error "(3) Fail to rmdir $DIR/$tdir/d0/foo"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	rmdir $DIR/$tdir/d0 || error "(4) Fail to unlink the dir d0"
	ls -ail $DIR/$tdir/d0 > /dev/null 2>&1 && "(5) 'ls' should fail"

	echo "Trigger namespace LFSCK to repair the missing remote name entry"
	$START_NAMESPACE -r -A ||
		error "(6) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(7) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^lost_dirent_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(8) Fail to repair lost dirent: $repaired"

	ls -ail $MOUNT/.lustre/lost+found/

	echo "There should be an orphan under .lustre/lost+found/MDT0001/"
	[ -d $MOUNT/.lustre/lost+found/MDT0001 ] ||
		error "(9) $MOUNT/.lustre/lost+found/MDT0001/ should be there"

	ls -ail $MOUNT/.lustre/lost+found/MDT0001/

	cname=$(find $MOUNT/.lustre/lost+found/MDT0001/ -name *-P-*)
	[ ! -z "$cname" ] ||
		error "(10) .lustre/lost+found/MDT0001/ should not be empty"
}
run_test 27b "LFSCK can recreate the lost remote parent directory as orphan"

test_28() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "The test needs at least 2 MDTs" && return

	echo "#####"
	echo "The target name entry is lost. The LFSCK should insert the"
	echo "orphan MDT-object under .lustre/lost+found/MDTxxxx. But if"
	echo "the MDT (on which the orphan MDT-object resides) has ever"
	echo "failed to respond some name entry verification during the"
	echo "first stage-scanning, then the LFSCK should skip to handle"
	echo "orphan MDT-object on this MDT. But other MDTs should not"
	echo "be affected."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/d1
	$LFS mkdir -i 1 $DIR/$tdir/d1/a1
	$LFS mkdir -i 1 $DIR/$tdir/d1/a2

	$LFS mkdir -i 1 $DIR/$tdir/d2
	$LFS mkdir -i 0 $DIR/$tdir/d2/a1
	$LFS mkdir -i 0 $DIR/$tdir/d2/a2

	echo "Inject failure stub on MDT0 to simulate the case that"
	echo "d1/a1's name entry will be removed, but the d1/a1's object"
	echo "and its linkEA are kept in the system. And the case that"
	echo "d2/a2's name entry will be removed, but the d2/a2's object"
	echo "and its linkEA are kept in the system."

	#define OBD_FAIL_LFSCK_NO_NAMEENTRY	0x1624
	do_facet mds1 $LCTL set_param fail_loc=0x1624
	do_facet mds2 $LCTL set_param fail_loc=0x1624
	rmdir $DIR/$tdir/d1/a1 || error "(1) Fail to rmdir $DIR/$tdir/d1/a1"
	rmdir $DIR/$tdir/d2/a2 || error "(2) Fail to rmdir $DIR/$tdir/d2/a2"
	do_facet mds1 $LCTL set_param fail_loc=0
	do_facet mds2 $LCTL set_param fail_loc=0

	cancel_lru_locks mdc
	cancel_lru_locks osc

	echo "Inject failure, to simulate the MDT0 fail to handle"
	echo "MDT1 LFSCK request during the first-stage scanning."
	#define OBD_FAIL_LFSCK_BAD_NETWORK	0x161c
	do_facet mds2 $LCTL set_param fail_loc=0x161c fail_val=0

	echo "Trigger namespace LFSCK on all devices to find out orphan object"
	$START_NAMESPACE -r -A ||
		error "(3) Fail to start LFSCK for namespace"

	wait_update_facet mds1 "$LCTL get_param -n \
		mdd.$(facet_svc mds1).lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "partial" 32 || {
		error "(4) mds1 is not the expected 'partial'"
	}

	wait_update_facet mds2 "$LCTL get_param -n \
		mdd.$(facet_svc mds2).lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		error "(5) mds2 is not the expected 'completed'"
	}

	do_facet mds2 $LCTL set_param fail_loc=0 fail_val=0

	local repaired=$(do_facet mds1 $LCTL get_param -n \
			 mdd.$(facet_svc mds1).lfsck_namespace |
			 awk '/^lost_dirent_repaired/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(6) Expect 0 fixed on mds1, but got: $repaired"

	repaired=$(do_facet mds2 $LCTL get_param -n \
		   mdd.$(facet_svc mds2).lfsck_namespace |
		   awk '/^lost_dirent_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(7) Expect 1 fixed on mds2, but got: $repaired"

	echo "Trigger namespace LFSCK on all devices again to cleanup"
	$START_NAMESPACE -r -A ||
		error "(8) Fail to start LFSCK for namespace"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_namespace |
			awk '/^status/ { print \\\$2 }'" "completed" 32 ||
			error "(9) MDS${k} is not the expected 'completed'"
	done

	local repaired=$(do_facet mds1 $LCTL get_param -n \
			 mdd.$(facet_svc mds1).lfsck_namespace |
			 awk '/^lost_dirent_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(10) Expect 1 fixed on mds1, but got: $repaired"

	repaired=$(do_facet mds2 $LCTL get_param -n \
		   mdd.$(facet_svc mds2).lfsck_namespace |
		   awk '/^lost_dirent_repaired/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(11) Expect 0 fixed on mds2, but got: $repaired"
}
run_test 28 "Skip the failed MDT(s) when handle orphan MDT-objects"

test_29a() {
	echo "#####"
	echo "The object's nlink attribute is larger than the object's known"
	echo "name entries count. The LFSCK will repair the object's nlink"
	echo "attribute to match the known name entries count"
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0"
	touch $DIR/$tdir/d0/foo || error "(2) Fail to create foo"

	echo "Inject failure stub on MDT0 to simulate the case that foo's"
	echo "nlink attribute is larger than its name entries count."

	#define OBD_FAIL_LFSCK_MORE_NLINK	0x1625
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1625
	ln $DIR/$tdir/d0/foo $DIR/$tdir/d0/h1 ||
		error "(3) Fail to hard link to $DIR/$tdir/d0/foo"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	cancel_lru_locks mdc
	local count=$(stat --format=%h $DIR/$tdir/d0/foo)
	[ $count -eq 3 ] || error "(4) Cannot inject error: $count"

	echo "Trigger namespace LFSCK to repair the nlink count"
	$START_NAMESPACE -r -A ||
		error "(5) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(6) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^nlinks_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(7) Fail to repair nlink count: $repaired"

	cancel_lru_locks mdc
	count=$(stat --format=%h $DIR/$tdir/d0/foo)
	[ $count -eq 2 ] || error "(8) Fail to repair nlink count: $count"
}
run_test 29a "LFSCK can repair bad nlink count (1)"

test_29b() {
	echo "#####"
	echo "The object's nlink attribute is smaller than the object's known"
	echo "name entries count. The LFSCK will repair the object's nlink"
	echo "attribute to match the known name entries count"
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0"
	touch $DIR/$tdir/d0/foo || error "(2) Fail to create foo"

	echo "Inject failure stub on MDT0 to simulate the case that foo's"
	echo "nlink attribute is smaller than its name entries count."

	#define OBD_FAIL_LFSCK_LESS_NLINK	0x1626
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1626
	ln $DIR/$tdir/d0/foo $DIR/$tdir/d0/h1 ||
		error "(3) Fail to hard link to $DIR/$tdir/d0/foo"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	cancel_lru_locks mdc
	local count=$(stat --format=%h $DIR/$tdir/d0/foo)
	[ $count -eq 1 ] || error "(4) Cannot inject error: $count"

	echo "Trigger namespace LFSCK to repair the nlink count"
	$START_NAMESPACE -r -A ||
		error "(5) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(6) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^nlinks_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(7) Fail to repair nlink count: $repaired"

	cancel_lru_locks mdc
	count=$(stat --format=%h $DIR/$tdir/d0/foo)
	[ $count -eq 2 ] || error "(8) Fail to repair nlink count: $count"
}
run_test 29b "LFSCK can repair bad nlink count (2)"

test_29c() {
	echo "#####"
	echo "There are too many hard links to the object, and exceeds the"
	echo "object's linkEA limitation, as to NOT all the known name entries"
	echo "will be recorded in the linkEA. Under such case, LFSCK should"
	echo "skip the nlink verification for this object."
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0"
	touch $DIR/$tdir/d0/foo || error "(2) Fail to create foo"
	ln $DIR/$tdir/d0/foo $DIR/$tdir/d0/h1 ||
		error "(3) Fail to hard link to $DIR/$tdir/d0/foo"

	echo "Inject failure stub on MDT0 to simulate the case that"
	echo "foo's hard links exceed the object's linkEA limitation."

	#define OBD_FAIL_LFSCK_LINKEA_OVERFLOW	0x1627
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1627
	ln $DIR/$tdir/d0/foo $DIR/$tdir/d0/h2 ||
		error "(4) Fail to hard link to $DIR/$tdir/d0/foo"

	cancel_lru_locks mdc

	local count1=$(stat --format=%h $DIR/$tdir/d0/foo)
	[ $count1 -eq 3 ] || error "(5) Stat failure: $count1"

	local foofid=$($LFS path2fid $DIR/$tdir/d0/foo)
	$LFS fid2path $DIR $foofid
	local count2=$($LFS fid2path $DIR $foofid | wc -l)
	[ $count2 -eq 2 ] || "(6) Fail to inject error: $count2"

	echo "Trigger namespace LFSCK to repair the nlink count"
	$START_NAMESPACE -r -A ||
		error "(7) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(8) unexpected status"
	}

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	local repaired=$($SHOW_NAMESPACE |
			 awk '/^nlinks_repaired/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(9) Repair nlink count unexpcetedly: $repaired"

	cancel_lru_locks mdc

	count1=$(stat --format=%h $DIR/$tdir/d0/foo)
	[ $count1 -eq 3 ] || error "(10) Stat failure: $count1"

	count2=$($LFS fid2path $DIR $foofid | wc -l)
	[ $count2 -eq 2 ] ||
		error "(11) Repaired something unexpectedly: $count2"
}
run_test 29c "Not verify nlink attr if hark links exceed linkEA limitation"

test_30() {
	[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
		skip "Only support backend /lost+found for ldiskfs" && return

	echo "#####"
	echo "The namespace LFSCK will move the orphans from backend"
	echo "/lost+found directory to normal client visible namespace"
	echo "or to global visible ./lustre/lost+found/MDTxxxx/ directory"
	echo "#####"

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/foo || error "(1) Fail to mkdir foo"
	touch $DIR/$tdir/foo/f0 || error "(2) Fail to touch f1"

	echo "Inject failure stub on MDT0 to simulate the case that"
	echo "directory d0 has no linkEA entry, then the LFSCK will"
	echo "move it into .lustre/lost+found/MDTxxxx/ later."

	#define OBD_FAIL_LFSCK_NO_LINKEA	0x161d
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x161d
	mkdir $DIR/$tdir/foo/d0 || error "(3) Fail to mkdir d0"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	touch $DIR/$tdir/foo/d0/f1 || error "(4) Fail to touch f1"
	mkdir $DIR/$tdir/foo/d0/d1 || error "(5) Fail to mkdir d1"

	echo "Inject failure stub on MDT0 to simulate the case that the"
	echo "object's name entry will be removed, but not destroy the"
	echo "object. Then backend e2fsck will handle it as orphan and"
	echo "add them into the backend /lost+found directory."

	#define OBD_FAIL_LFSCK_NO_NAMEENTRY	0x1624
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1624
	rmdir $DIR/$tdir/foo/d0/d1 || error "(6) Fail to rmdir d1"
	rm -f $DIR/$tdir/foo/d0/f1 || error "(7) Fail to unlink f1"
	rmdir $DIR/$tdir/foo/d0 || error "(8) Fail to rmdir d0"
	rm -f $DIR/$tdir/foo/f0 || error "(9) Fail to unlink f0"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	umount_client $MOUNT || error "(10) Fail to stop client!"

	stop $SINGLEMDS || error "(11) Fail to stop MDT0"

	echo "run e2fsck"
	run_e2fsck $(facet_host $SINGLEMDS) $MDT_DEVNAME "-y" ||
		error "(12) Fail to run e2fsck"

	start $SINGLEMDS $MDT_DEVNAME $MOUNT_OPTS_NOSCRUB > /dev/null ||
		error "(13) Fail to start MDT0"

	echo "Trigger namespace LFSCK to recover backend orphans"
	$START_NAMESPACE -r -A ||
		error "(14) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(15) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^local_lost_found_moved/ { print $2 }')
	[ $repaired -ge 4 ] ||
		error "(16) Fail to recover backend orphans: $repaired"

	mount_client $MOUNT || error "(17) Fail to start client!"

	stat $DIR/$tdir/foo/f0 || "(18) f0 is not recovered"

	ls -ail $MOUNT/.lustre/lost+found/

	echo "d0 should become orphan under .lustre/lost+found/MDT0000/"
	[ -d $MOUNT/.lustre/lost+found/MDT0000 ] ||
		error "(19) $MOUNT/.lustre/lost+found/MDT0000/ should be there"

	ls -ail $MOUNT/.lustre/lost+found/MDT0000/

	cname=$(find $MOUNT/.lustre/lost+found/MDT0000/ -name *-*-D-*)
	[ ! -z "$cname" ] || error "(20) d0 is not recovered"

	stat ${cname}/d1 || error "(21) d0 is not recovered"
	stat ${cname}/f1 || error "(22) f1 is not recovered"
}
run_test 30 "LFSCK can recover the orphans from backend /lost+found"

test_31a() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "The test needs at least 2 MDTs" && return

	echo "#####"
	echo "For the name entry under a striped directory, if the name"
	echo "hash does not match the shard, then the LFSCK will repair"
	echo "the bad name entry"
	echo "#####"

	check_mount_and_prep

	$LFS setdirstripe -i 0 -c $MDSCOUNT $DIR/$tdir/striped_dir ||
		error "(1) Fail to create striped directory"

	echo "Inject failure stub on client to simulate the case that"
	echo "some name entry should be inserted into other non-first"
	echo "shard, but inserted into the first shard by wrong"

	#define OBD_FAIL_LFSCK_BAD_NAME_HASH	0x1628
	$LCTL set_param fail_loc=0x1628 fail_val=0
	createmany -d $DIR/$tdir/striped_dir/d $MDSCOUNT ||
		error "(2) Fail to create file under striped directory"
	$LCTL set_param fail_loc=0 fail_val=0

	echo "Trigger namespace LFSCK to repair bad name hash"
	$START_NAMESPACE -r -A ||
		error "(3) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(4) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^name_hash_repaired/ { print $2 }')
	[ $repaired -ge 1 ] ||
		error "(5) Fail to repair bad name hash: $repaired"

	umount_client $MOUNT || error "(6) umount failed"
	mount_client $MOUNT || error "(7) mount failed"

	for ((i = 0; i < $MDSCOUNT; i++)); do
		stat $DIR/$tdir/striped_dir/d$i ||
			error "(8) Fail to stat d$i after LFSCK"
		rmdir $DIR/$tdir/striped_dir/d$i ||
			error "(9) Fail to unlink d$i after LFSCK"
	done

	rmdir $DIR/$tdir/striped_dir ||
		error "(10) Fail to remove the striped directory after LFSCK"
}
run_test 31a "The LFSCK can find/repair the name entry with bad name hash (1)"

test_31b() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "The test needs at least 2 MDTs" && return

	echo "#####"
	echo "For the name entry under a striped directory, if the name"
	echo "hash does not match the shard, then the LFSCK will repair"
	echo "the bad name entry"
	echo "#####"

	check_mount_and_prep

	$LFS setdirstripe -i 0 -c $MDSCOUNT $DIR/$tdir/striped_dir ||
		error "(1) Fail to create striped directory"

	echo "Inject failure stub on client to simulate the case that"
	echo "some name entry should be inserted into other non-second"
	echo "shard, but inserted into the secod shard by wrong"

	#define OBD_FAIL_LFSCK_BAD_NAME_HASH	0x1628
	$LCTL set_param fail_loc=0x1628 fail_val=1
	createmany -d $DIR/$tdir/striped_dir/d $MDSCOUNT ||
		error "(2) Fail to create file under striped directory"
	$LCTL set_param fail_loc=0 fail_val=0

	echo "Trigger namespace LFSCK to repair bad name hash"
	$START_NAMESPACE -r -A ||
		error "(3) Fail to start LFSCK for namespace"

	wait_update_facet mds2 "$LCTL get_param -n \
		mdd.$(facet_svc mds2).lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 ||
		error "(4) unexpected status"

	local repaired=$(do_facet mds2 $LCTL get_param -n \
			 mdd.$(facet_svc mds2).lfsck_namespace |
			 awk '/^name_hash_repaired/ { print $2 }')
	[ $repaired -ge 1 ] ||
		error "(5) Fail to repair bad name hash: $repaired"

	umount_client $MOUNT || error "(6) umount failed"
	mount_client $MOUNT || error "(7) mount failed"

	for ((i = 0; i < $MDSCOUNT; i++)); do
		stat $DIR/$tdir/striped_dir/d$i ||
			error "(8) Fail to stat d$i after LFSCK"
		rmdir $DIR/$tdir/striped_dir/d$i ||
			error "(9) Fail to unlink d$i after LFSCK"
	done

	rmdir $DIR/$tdir/striped_dir ||
		error "(10) Fail to remove the striped directory after LFSCK"
}
run_test 31b "The LFSCK can find/repair the name entry with bad name hash (2)"

test_31c() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "The test needs at least 2 MDTs" && return

	echo "#####"
	echo "For some reason, the master MDT-object of the striped directory"
	echo "may lost its master LMV EA. If nobody created files under the"
	echo "master directly after the master LMV EA lost, then the LFSCK"
	echo "should re-generate the master LMV EA."
	echo "#####"

	check_mount_and_prep

	echo "Inject failure stub on MDT0 to simulate the case that the"
	echo "master MDT-object of the striped directory lost the LMV EA."

	#define OBD_FAIL_LFSCK_LOST_MASTER_LMV	0x1629
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1629
	$LFS setdirstripe -i 0 -c $MDSCOUNT $DIR/$tdir/striped_dir ||
		error "(1) Fail to create striped directory"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	echo "Trigger namespace LFSCK to re-generate master LMV EA"
	$START_NAMESPACE -r -A ||
		error "(2) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(3) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^striped_dirs_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(4) Fail to re-generate master LMV EA: $repaired"

	umount_client $MOUNT || error "(5) umount failed"
	mount_client $MOUNT || error "(6) mount failed"

	local empty=$(ls $DIR/$tdir/striped_dir/)
	[ -z "$empty" ] || error "(7) The master LMV EA is not repaired: $empty"

	rmdir $DIR/$tdir/striped_dir ||
		error "(8) Fail to remove the striped directory after LFSCK"
}
run_test 31c "Re-generate the lost master LMV EA for striped directory"

test_31d() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "The test needs at least 2 MDTs" && return

	echo "#####"
	echo "For some reason, the master MDT-object of the striped directory"
	echo "may lost its master LMV EA. If somebody created files under the"
	echo "master directly after the master LMV EA lost, then the LFSCK"
	echo "should NOT re-generate the master LMV EA, instead, it should"
	echo "change the broken striped dirctory as read-only to prevent"
	echo "further damage"
	echo "#####"

	check_mount_and_prep

	echo "Inject failure stub on MDT0 to simulate the case that the"
	echo "master MDT-object of the striped directory lost the LMV EA."

	#define OBD_FAIL_LFSCK_LOST_MASTER_LMV	0x1629
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1629
	$LFS setdirstripe -i 0 -c $MDSCOUNT $DIR/$tdir/striped_dir ||
		error "(1) Fail to create striped directory"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x0

	umount_client $MOUNT || error "(2) umount failed"
	mount_client $MOUNT || error "(3) mount failed"

	touch $DIR/$tdir/striped_dir/dummy ||
		error "(4) Fail to touch under broken striped directory"

	echo "Trigger namespace LFSCK to find out the inconsistency"
	$START_NAMESPACE -r -A ||
		error "(5) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(6) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^striped_dirs_repaired/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(7) Re-generate master LMV EA unexpected: $repaired"

	stat $DIR/$tdir/striped_dir/dummy ||
		error "(8) Fail to stat $DIR/$tdir/striped_dir/dummy"

	touch $DIR/$tdir/striped_dir/foo &&
		error "(9) The broken striped directory should be read-only"

	chattr -i $DIR/$tdir/striped_dir ||
		error "(10) Fail to chattr on the broken striped directory"

	rmdir $DIR/$tdir/striped_dir ||
		error "(11) Fail to remove the striped directory after LFSCK"
}
run_test 31d "Set broken striped directory (modified after broken) as read-only"

test_31e() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "The test needs at least 2 MDTs" && return

	echo "#####"
	echo "For some reason, the slave MDT-object of the striped directory"
	echo "may lost its slave LMV EA. The LFSCK should re-generate the"
	echo "slave LMV EA."
	echo "#####"

	check_mount_and_prep

	echo "Inject failure stub on MDT0 to simulate the case that the"
	echo "slave MDT-object (that resides on the same MDT as the master"
	echo "MDT-object resides on) lost the LMV EA."

	#define OBD_FAIL_LFSCK_LOST_SLAVE_LMV	0x162a
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x162a fail_val=0
	$LFS setdirstripe -i 0 -c $MDSCOUNT $DIR/$tdir/striped_dir ||
		error "(1) Fail to create striped directory"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x0 fail_val=0

	echo "Trigger namespace LFSCK to re-generate slave LMV EA"
	$START_NAMESPACE -r -A ||
		error "(2) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(3) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^striped_shards_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(4) Fail to re-generate slave LMV EA: $repaired"

	rmdir $DIR/$tdir/striped_dir ||
		error "(5) Fail to remove the striped directory after LFSCK"
}
run_test 31e "Re-generate the lost slave LMV EA for striped directory (1)"

test_31f() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "The test needs at least 2 MDTs" && return

	echo "#####"
	echo "For some reason, the slave MDT-object of the striped directory"
	echo "may lost its slave LMV EA. The LFSCK should re-generate the"
	echo "slave LMV EA."
	echo "#####"

	check_mount_and_prep

	echo "Inject failure stub on MDT0 to simulate the case that the"
	echo "slave MDT-object (that resides on different MDT as the master"
	echo "MDT-object resides on) lost the LMV EA."

	#define OBD_FAIL_LFSCK_LOST_SLAVE_LMV	0x162a
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x162a fail_val=1
	$LFS setdirstripe -i 0 -c $MDSCOUNT $DIR/$tdir/striped_dir ||
		error "(1) Fail to create striped directory"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x0 fail_val=0

	echo "Trigger namespace LFSCK to re-generate slave LMV EA"
	$START_NAMESPACE -r -A ||
		error "(2) Fail to start LFSCK for namespace"

	wait_update_facet mds2 "$LCTL get_param -n \
		mdd.$(facet_svc mds2).lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 ||
		error "(3) unexpected status"

	local repaired=$(do_facet mds2 $LCTL get_param -n \
			 mdd.$(facet_svc mds2).lfsck_namespace |
			 awk '/^striped_shards_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(4) Fail to re-generate slave LMV EA: $repaired"

	rmdir $DIR/$tdir/striped_dir ||
		error "(5) Fail to remove the striped directory after LFSCK"
}
run_test 31f "Re-generate the lost slave LMV EA for striped directory (2)"

test_31g() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "The test needs at least 2 MDTs" && return

	echo "#####"
	echo "For some reason, the stripe index in the slave LMV EA is"
	echo "corrupted. The LFSCK should repair the slave LMV EA."
	echo "#####"

	check_mount_and_prep

	echo "Inject failure stub on MDT0 to simulate the case that the"
	echo "slave LMV EA on the first shard of the striped directory"
	echo "claims the same index as the second shard claims"

	#define OBD_FAIL_LFSCK_BAD_SLAVE_LMV	0x162b
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x162b fail_val=0
	$LFS setdirstripe -i 0 -c $MDSCOUNT $DIR/$tdir/striped_dir ||
		error "(1) Fail to create striped directory"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x0 fail_val=0

	echo "Trigger namespace LFSCK to repair the slave LMV EA"
	$START_NAMESPACE -r -A ||
		error "(2) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(3) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^striped_shards_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(4) Fail to repair slave LMV EA: $repaired"

	umount_client $MOUNT || error "(5) umount failed"
	mount_client $MOUNT || error "(6) mount failed"

	touch $DIR/$tdir/striped_dir/foo ||
		error "(7) Fail to touch file after the LFSCK"

	rm -f $DIR/$tdir/striped_dir/foo ||
		error "(8) Fail to unlink file after the LFSCK"

	rmdir $DIR/$tdir/striped_dir ||
		error "(9) Fail to remove the striped directory after LFSCK"
}
run_test 31g "Repair the corrupted slave LMV EA"

test_31h() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "The test needs at least 2 MDTs" && return

	echo "#####"
	echo "For some reason, the shard's name entry in the striped"
	echo "directory may be corrupted. The LFSCK should repair the"
	echo "bad shard's name entry."
	echo "#####"

	check_mount_and_prep

	echo "Inject failure stub on MDT0 to simulate the case that the"
	echo "first shard's name entry in the striped directory claims"
	echo "the same index as the second shard's name entry claims."

	#define OBD_FAIL_LFSCK_BAD_SLAVE_NAME	0x162c
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x162c fail_val=0
	$LFS setdirstripe -i 0 -c $MDSCOUNT $DIR/$tdir/striped_dir ||
		error "(1) Fail to create striped directory"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x0 fail_val=0

	echo "Trigger namespace LFSCK to repair the shard's name entry"
	$START_NAMESPACE -r -A ||
		error "(2) Fail to start LFSCK for namespace"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(3) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^dirent_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(4) Fail to repair shard's name entry: $repaired"

	umount_client $MOUNT || error "(5) umount failed"
	mount_client $MOUNT || error "(6) mount failed"

	touch $DIR/$tdir/striped_dir/foo ||
		error "(7) Fail to touch file after the LFSCK"

	rm -f $DIR/$tdir/striped_dir/foo ||
		error "(8) Fail to unlink file after the LFSCK"

	rmdir $DIR/$tdir/striped_dir ||
		error "(9) Fail to remove the striped directory after LFSCK"
}
run_test 31h "Repair the corrupted shard's name entry"

test_32()
{
	lfsck_prep 5 5
	umount_client $MOUNT

	#define OBD_FAIL_LFSCK_ASSISTANT_DIRECT	0x162d
	do_facet $SINGLEMDS $LCTL set_param fail_val=3 fail_loc=0x162d
	$START_LAYOUT -r || error "(2) Fail to start LFSCK for layout!"

	local STATUS=$($SHOW_LAYOUT | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(3) Expect 'scanning-phase1', but got '$STATUS'"

	echo "stop ost1"
	stop ost1 > /dev/null || error "(4) Fail to stop OST1!"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	sleep 1

	echo "stop LFSCK"
	$STOP_LFSCK || error "(5) Fail to stop LFSCK!"
}
run_test 32 "stop LFSCK when some OST failed"

# restore MDS/OST size
MDSSIZE=${SAVED_MDSSIZE}
OSTSIZE=${SAVED_OSTSIZE}
OSTCOUNT=${SAVED_OSTCOUNT}

# cleanup the system at last
formatall

complete $SECONDS
exit_status
