#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

# bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_LFSCK_EXCEPT "
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
build_test_filter

require_dsh_mds || exit 0

load_modules

if ! check_versions; then
	skip "It is NOT necessary to test lfsck under interoperation mode"
	exit 0
fi

(( $MDS1_VERSION >= $(version_code 2.3.60) )) ||
	skip "Need MDS version at least 2.3.60"

LTIME=${LTIME:-120}

SAVED_MDSSIZE=${MDSSIZE}
SAVED_OSTSIZE=${OSTSIZE}
SAVED_OSTCOUNT=${OSTCOUNT}
# use small MDS + OST size to speed formatting time
# do not use too small MDSSIZE/OSTSIZE, which affect the default journal size
MDSSIZE=100000
[ "$mds1_FSTYPE" == zfs ] && MDSSIZE=300000
OSTSIZE=100000
[ "$ost1_FSTYPE" == zfs ] && OSTSIZE=300000

# no need too many OSTs, to reduce the format/start/stop overhead
cleanupall
[ $OSTCOUNT -gt 4 ] && OSTCOUNT=4

# build up a clean test environment.
REFORMAT="yes" check_and_setup_lustre

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
MOUNT_OPTS_SCRUB="$MDS_MOUNT_OPTS -o user_xattr"
MOUNT_OPTS_NOSCRUB="$MDS_MOUNT_OPTS -o user_xattr,noscrub"
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
	[ $mds1_FSTYPE == ldiskfs ] || return 0

	stop $SINGLEMDS > /dev/null || error "(0) Fail to the stop MDT0"
	run_e2fsck $(facet_active_host $SINGLEMDS) $(mdsdevname 1) "-n" |
		grep "Fix? no" && {
		run_e2fsck $(facet_active_host $SINGLEMDS) $(mdsdevname 1) "-n"
		error "(2) Detected inconsistency on MDT0"
	}
	start $SINGLEMDS $MDT_DEVNAME $MOUNT_OPTS_NOSCRUB > /dev/null ||
		error "(3) Fail to start MDT0"
}

wait_all_targets_blocked() {
	local com=$1
	local status=$2
	local err=$3

	local count=$(do_facet mds1 \
		     "$LCTL lfsck_query -t $com -M ${FSNAME}-MDT0000 -w |
		      awk '/^${com}_mdts_${status}/ { print \\\$2 }'")
	[[ $count -eq $MDSCOUNT ]] || {
		do_facet mds1 "$LCTL lfsck_query -t $com -M ${FSNAME}-MDT0000"
		error "($err) only $count of $MDSCOUNT MDTs are in ${status}"
	}
}

wait_all_targets() {
	local com=$1
	local status=$2
	local err=$3

	wait_update_facet mds1 "$LCTL lfsck_query -t $com -M ${FSNAME}-MDT0000 |
		awk '/^${com}_mdts_${status}/ { print \\\$2 }'" \
		"$MDSCOUNT" $LTIME || {
		do_facet mds1 "$LCTL lfsck_query -t $com -M ${FSNAME}-MDT0000"
		error "($err) some MDTs are not in ${status}"
	}
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
	[ "$mds1_FSTYPE" != ldiskfs ] &&
		skip "OI Scrub not implemented for ZFS"

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

test_1c() {
	lfsck_prep 1 1

	#define OBD_FAIL_FID_IGIF	0x1504
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1504
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
		error "(5) Fail to repair lost FID-in-dirent: $repaired"

	run_e2fsck_on_mdt0

	mount_client $MOUNT || error "(6) Fail to start client!"

	#define OBD_FAIL_FID_LOOKUP	0x1505
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1505
	ls $DIR/$tdir/ > /dev/null || error "(7) no FID-in-dirent."

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
}
run_test 1c "LFSCK can find out and repair lost FID-in-dirent"

test_1d() {
	[ $MDS1_VERSION -lt $(version_code 2.13.57) ] &&
		skip "MDS older than 2.13.57"
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"

	check_mount_and_prep

	touch $DIR/$tdir/$tfile
	mkdir $DIR/$tdir/subdir
	$LFS mkdir -i 1 $DIR/$tdir/remotedir
	$LFS path2fid $DIR/$tdir
	ll_decode_linkea $DIR/$tdir/$tfile
	ll_decode_linkea $DIR/$tdir/subdir
	ll_decode_linkea $DIR/$tdir/remotedir

	local mntpt=$(facet_mntpt mds1)

	# unlink OI files to remove the stale entry
	local saved_opts=$MDS_MOUNT_OPTS

	stopall
	mount_fstype mds1 $mntpt
	# increase $tdir FID oid in LMA
	do_facet mds1 "getfattr -d -m trusted.lma -e hex \
		--absolute-names $mntpt/ROOT/$tdir | \
		sed -E 's/0(.{8})$/1\1/' | setfattr --restore=-"
	unmount_fstype mds1 $mntpt
	setupall

	# the FID oid in LMA was increased above, and it's not in OI table,
	# run scrub first to generate mapping in OI, so the following namespace
	# check can fix linkea correctly, this is not necessary normally.
	do_facet mds1 $LCTL lfsck_start -M ${MDT_DEV} -t scrub ||
		error "failed to start LFSCK for scrub!"
	wait_update_facet mds1 "$LCTL get_param -n \
		osd-*.$(facet_svc mds1).oi_scrub |
		awk '/^status/ { print \\\$2 }'" "completed" 32 ||
		error "unexpected status"

	$START_NAMESPACE -r -A || error "fail to start LFSCK for namespace!"
	wait_update_facet mds1 "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "unexpected status"
	}
	$LFS path2fid $DIR/$tdir
	ll_decode_linkea $DIR/$tdir/$tfile
	ll_decode_linkea $DIR/$tdir/subdir
	ll_decode_linkea $DIR/$tdir/remotedir

	local pfid
	local fid

	fid=$($LFS path2fid $DIR/$tdir)
	for f in $tfile subdir remotedir; do
		pfid=$(ll_decode_linkea $DIR/$tdir/$f |
			awk '/pfid/ { print $3 }')
		pfid=${pfid%,}
		[ "$pfid" == "$fid" ] || error "$fid in LMA != $pfid in linkea"
	done
}
run_test 1d "LFSCK can fix mismatch of FID in LMA and FID in child linkea"

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
	(( $MDS1_VERSION > $(version_code 2.4.90) )) ||
		skip "MDS older than 2.4.90"

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
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-4788"

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5511"

	check_mount_and_prep

	$LFS mkdir -i 1 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0 on MDT1"

	#define OBD_FAIL_LFSCK_LINKEA_CRASH	0x1603
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1603
	$LFS mkdir -i 0 $DIR/$tdir/d0/d1 || error "(2) Fail to mkdir d1 on MDT0"
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	$START_NAMESPACE -r -A || error "(3) Fail to start LFSCK for namespace!"

	wait_all_targets_blocked namespace completed 4

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
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-4788"

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
	[ "$mds1_FSTYPE" != ldiskfs ] &&
		skip "OI Scrub not implemented for ZFS"

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
	[ "$mds1_FSTYPE" != ldiskfs ] &&
		skip "OI Scrub not implemented for ZFS"

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

	echo "Additional debug for 6b"
	$SHOW_NAMESPACE
	if [ "$D_POS0" == "N/A" -o "$D_POS0" == "0x0" \
	     -o "$D_POS1" == "0x0" -o "$D_POS1" == "N/A" ]; then
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
	# MAX_MARGIN = 1.3 = 13 / 10
	local MAX_SPEED=$((BASE_SPEED1 * (RUN_TIME1 + TIME_DIFF) / \
			   RUN_TIME1 * 13 / 10))
	[ $SPEED -lt $MAX_SPEED ] || {
		$SHOW_LAYOUT
		log "speed1: $BASE_SPEED1 time1: $RUN_TIME1"
		error "(4) Speed $SPEED, expected < $MAX_SPEED"
	}

	# adjust speed limit
	local BASE_SPEED2=300
	local RUN_TIME2=10
	do_facet $SINGLEMDS \
		$LCTL set_param -n mdd.${MDT_DEV}.lfsck_speed_limit $BASE_SPEED2
	sleep $RUN_TIME2

	SPEED=$($SHOW_LAYOUT | awk '/^average_speed_phase1/ { print $2 }')
	# MIN_MARGIN = 0.7 = 7 / 10
	local MIN_SPEED=$(((BASE_SPEED1 * (RUN_TIME1 - TIME_DIFF) + \
			    BASE_SPEED2 * (RUN_TIME2 - TIME_DIFF)) / \
			   (RUN_TIME1 + RUN_TIME2) * 7 / 10))
	[ $SPEED -gt $MIN_SPEED ] || {
		if [ $mds1_FSTYPE != ldiskfs ]; then
			error_ignore LU-5624 \
			"(5.1) Got speed $SPEED, expected more than $MIN_SPEED"
		else
			error \
			"(5.2) Got speed $SPEED, expected more than $MIN_SPEED"
		fi
	}

	# MAX_MARGIN = 1.3 = 13 / 10
	MAX_SPEED=$(((BASE_SPEED1 * (RUN_TIME1 + TIME_DIFF) + \
		      BASE_SPEED2 * (RUN_TIME2 + TIME_DIFF)) / \
		     (RUN_TIME1 + RUN_TIME2) * 13 / 10))
	[ $SPEED -lt $MAX_SPEED ] || {
		$SHOW_LAYOUT
		log "speed1: $BASE_SPEED1 time1: $RUN_TIME1"
		log "speed2: $BASE_SPEED2 time2: $RUN_TIME2"
		error "(6) Speed $SPEED, expected < $MAX_SPEED"
	}

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param -n mdd.*.lfsck_speed_limit 0
	do_nodes $(comma_list $(osts_nodes)) \
		$LCTL set_param -n obdfilter.*.lfsck_speed_limit 0

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
	# MAX_MARGIN = 1.3 = 13 / 10
	local MAX_SPEED=$((BASE_SPEED1 * (RUN_TIME1 + TIME_DIFF) / \
			  RUN_TIME1 * 13 / 10))
	[ $SPEED -lt $MAX_SPEED ] || {
		$SHOW_NAMESPACE
		log "speed1: $BASE_SPEED1 time1: $RUN_TIME1"
		error "(8) Speed $SPEED, expected < $MAX_SPEED"
	}

	# adjust speed limit
	local BASE_SPEED2=150
	local RUN_TIME2=10
	do_facet $SINGLEMDS \
		$LCTL set_param -n mdd.${MDT_DEV}.lfsck_speed_limit $BASE_SPEED2
	sleep $RUN_TIME2

	SPEED=$($SHOW_NAMESPACE | awk '/^average_speed_phase2/ { print $2 }')
	# MIN_MARGIN = 0.7 = 7 / 10
	local MIN_SPEED=$(((BASE_SPEED1 * (RUN_TIME1 - TIME_DIFF) + \
			    BASE_SPEED2 * (RUN_TIME2 - TIME_DIFF)) / \
			   (RUN_TIME1 + RUN_TIME2) * 7 / 10))
	[ $SPEED -gt $MIN_SPEED ] || {
		if [ $mds1_FSTYPE != ldiskfs ]; then
			error_ignore LU-5624 \
			"(9.1) Got speed $SPEED, expected more than $MIN_SPEED"
		else
			error \
			"(9.2) Got speed $SPEED, expected more than $MIN_SPEED"
		fi
	}

	# MAX_MARGIN = 1.3 = 13 / 10
	MAX_SPEED=$(((BASE_SPEED1 * (RUN_TIME1 + TIME_DIFF) + \
		      BASE_SPEED2 * (RUN_TIME2 + TIME_DIFF)) / \
		     (RUN_TIME1 + RUN_TIME2) * 13 / 10))
	[ $SPEED -lt $MAX_SPEED ] || {
		$SHOW_NAMESPACE
		log "speed1: $BASE_SPEED1 time1: $RUN_TIME1"
		log "speed2: $BASE_SPEED2 time2: $RUN_TIME2"
		error "(10) Speed $SPEED, expected < $MAX_SPEED"
	}

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param -n mdd.*.lfsck_speed_limit 0
	do_nodes $(comma_list $(osts_nodes)) \
		$LCTL set_param -n obdfilter.*.lfsck_speed_limit 0
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
	[[ $mds1_FSTYPE == ldiskfs ]] || skip "lookup(..)/linkea on ZFS issue"

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

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param -n mdd.*.lfsck_speed_limit 0
	do_nodes $(comma_list $(osts_nodes)) \
		$LCTL set_param -n obdfilter.*.lfsck_speed_limit 0
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
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-1267"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir
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
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-1267"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	echo "set fail_loc=0x160d to skip the updating LAST_ID on-disk"
	#define OBD_FAIL_LFSCK_SKIP_LASTID	0x160d
	do_facet ost1 $LCTL set_param fail_loc=0x160d

	local count=$(precreated_ost_obj_count 0 0)

	createmany -o $DIR/$tdir/f $((count + 32))

	local proc_path="${FSNAME}-OST0000-osc-MDT0000"
	local seq=$(do_facet mds1 $LCTL get_param -n \
		    osp.${proc_path}.prealloc_last_seq)
	local id_used=$(do_facet mds1 $LCTL get_param -n \
			osp.${proc_path}.prealloc_last_id)

	umount_client $MOUNT
	stop ost1 || error "(1) Fail to stop ost1"

	#define OBD_FAIL_OST_ENOSPC              0x215
	do_facet ost1 $LCTL set_param fail_loc=0x215

	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS ||
		error "(2) Fail to start ost1"

	for ((i = 0; i < 60; i++)); do
		id_ost1=$(do_facet ost1 \
			  "$LCTL get_param -n obdfilter.$ost1_svc.last_id" |
			  awk -F: "/$seq/ { print \$2 }")
		[ -n "$id_ost1" ] && break
		sleep 1
	done

	echo "the on-disk LAST_ID should be smaller than the expected one"
	[ $id_used -gt $id_ost1 ] ||
		error "(4) expect id_used '$id_used' > id_ost1 '$id_ost1'"

	echo "trigger LFSCK for layout on ost1 to rebuild the on-disk LAST_ID"
	$START_LAYOUT_ON_OST -r || error "(5) Fail to start LFSCK on OST!"

	wait_update_facet ost1 \
		"$LCTL get_param -n obdfilter.$ost1_svc.lfsck_layout |
		 awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT_ON_OST
		error "(6) unexpected status"
	}

	stop ost1 || error "(7) Fail to stop ost1"

	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS ||
		error "(8) Fail to start ost1"

	echo "the on-disk LAST_ID should have been rebuilt"
	# last_id may be larger than $id_used if objects were created/skipped
	wait_update_facet_cond ost1 \
		"$LCTL get_param -n obdfilter.$ost1_svc.last_id |
		 awk -F: '/$seq/ { print \\\$2 }'" "-ge" "$id_used" 60 || {
		do_facet ost1 $LCTL get_param obdfilter.$ost1_svc.last_id
		error "(9) expect last_id >= id_used $seq:$id_used"
	}

	do_facet ost1 $LCTL set_param fail_loc=0
	stopall || error "(10) Fail to stopall"
}
run_test 11b "LFSCK can rebuild crashed last_id"

test_12a() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3950"

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
	wait_all_targets namespace scanning-phase1 3

	echo "Stop namespace LFSCK on all targets by single lctl command."
	do_facet mds1 $LCTL lfsck_stop -M ${FSNAME}-MDT0000 -A ||
		error "(4) Fail to stop LFSCK on all devices!"

	echo "All the LFSCK targets should be in 'stopped' status."
	wait_all_targets_blocked namespace stopped 5

	echo "Re-start namespace LFSCK on all targets by single command (-s 0)."
	do_facet mds1 $LCTL lfsck_start -M ${FSNAME}-MDT0000 -t namespace -A \
		-s 0 -r || error "(6) Fail to start LFSCK on all devices!"

	echo "All the LFSCK targets should be in 'completed' status."
	wait_all_targets_blocked namespace completed 7

	start_full_debug_logging

	echo "Start layout LFSCK on all targets by single command (-s 1)."
	do_facet mds1 $LCTL lfsck_start -M ${FSNAME}-MDT0000 -t layout -A \
		-s 1 -r || error "(8) Fail to start LFSCK on all devices!"

	echo "All the LFSCK targets should be in 'scanning-phase1' status."
	wait_all_targets layout scanning-phase1 9

	echo "Stop layout LFSCK on all targets by single lctl command."
	do_facet mds1 $LCTL lfsck_stop -M ${FSNAME}-MDT0000 -A ||
		error "(10) Fail to stop LFSCK on all devices!"

	echo "All the LFSCK targets should be in 'stopped' status."
	wait_all_targets_blocked layout stopped 11

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
	wait_all_targets_blocked layout completed 14

	stop_full_debug_logging
}
run_test 12a "single command to trigger LFSCK on all devices"

test_12b() {
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3950"

	check_mount_and_prep

	echo "Start LFSCK without '-M' specified."
	do_facet mds1 $LCTL lfsck_start -A -r ||
		error "(0) Fail to start LFSCK without '-M'"

	wait_all_targets_blocked namespace completed 1
	wait_all_targets_blocked layout completed 2

	local count=$(do_facet mds1 $LCTL dl |
		      awk '{ print $3 }' | grep mdt | wc -l)
	if [ $count -gt 1 ]; then
		echo
		echo "Start layout LFSCK on the node with multipe targets,"
		echo "but not specify '-M'/'-A' option. Should get failure."
		echo
		do_facet mds1 $LCTL lfsck_start -t layout -r &&
			error "(3) Start layout LFSCK should fail" || true
	fi
}
run_test 12b "auto detect Lustre device"

test_13() {
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3593"

	echo "#####"
	echo "The lmm_oi in layout EA should be consistent with the MDT-object"
	echo "FID; otherwise, the LFSCK should re-generate the lmm_oi from the"
	echo "MDT-object FID."
	echo "#####"

	check_mount_and_prep

	echo "Inject failure stub to simulate bad lmm_oi"
	#define OBD_FAIL_LFSCK_BAD_LMMOI	0x160f
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x160f
	createmany -o $DIR/$tdir/f 1
	$LFS setstripe -E 1M -S 1M -E -1 $DIR/$tdir/f1 ||
		error "(0) Fail to create PFL $DIR/$tdir/f1"
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
	[ $repaired -eq 2 ] ||
		error "(3) Fail to repair crashed lmm_oi: $repaired"
}
run_test 13 "LFSCK can repair crashed lmm_oi"

test_14a() {
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3590"

	echo "#####"
	echo "The OST-object referenced by the MDT-object should be there;"
	echo "otherwise, the LFSCK should re-create the missing OST-object."
	echo "without '--delay-create-ostobj' option."
	echo "#####"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	echo "Inject failure stub to simulate dangling referenced MDT-object"
	#define OBD_FAIL_LFSCK_DANGLING	0x1610
	do_facet ost1 $LCTL set_param fail_loc=0x1610
	local count=$(precreated_ost_obj_count 0 0)

	createmany -o $DIR/$tdir/f $((count + 16)) ||
		error "(0.1) Fail to create $DIR/$tdir/fx"
	touch $DIR/$tdir/guard0

	for ((i = 0; i < 16; i++)); do
		$LFS setstripe -E 512K -S 256K -o 0 -E 2M \
			$DIR/$tdir/f_comp${i} ||
			error "(0.2) Fail to create $DIR/$tdir/f_comp${i}"
	done
	touch $DIR/$tdir/guard1

	do_facet ost1 $LCTL set_param fail_loc=0

	start_full_debug_logging

	# exhaust other pre-created dangling cases
	count=$(precreated_ost_obj_count 0 0)
	createmany -o $DIR/$tdir/a $count ||
		error "(0.5) Fail to create $count files."

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
	stat $DIR/$tdir/guard0 > /dev/null 2>&1 &&
		error "(5.1) stat should fail"
	stat $DIR/$tdir/guard1 > /dev/null 2>&1 &&
		error "(5.2) stat should fail"

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
	wait_update_facet client "stat $DIR/$tdir/guard0 |
		awk '/Size/ { print \\\$2 }'" "0" 32 || {
		stat $DIR/$tdir/guard0
		$SHOW_LAYOUT
		error "(8.1) unexpected size"
	}

	wait_update_facet client "stat $DIR/$tdir/guard1 |
		awk '/Size/ { print \\\$2 }'" "0" 32 || {
		stat $DIR/$tdir/guard1
		$SHOW_LAYOUT
		error "(8.2) unexpected size"
	}

	repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_dangling/ { print $2 }')
	[ $repaired -ge 32 ] ||
		error "(9) Fail to repair dangling reference: $repaired"

	stop_full_debug_logging

	echo "stopall to cleanup object cache"
	stopall > /dev/null
	echo "setupall"
	setupall > /dev/null
}
run_test 14a "LFSCK can repair MDT-object with dangling LOV EA reference (1)"

test_14b() {
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3590"

	echo "#####"
	echo "The OST-object referenced by the MDT-object should be there;"
	echo "otherwise, the LFSCK should re-create the missing OST-object."
	echo "with '--delay-create-ostobj' option."
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
	$START_LAYOUT -r -o -d || error "(2) Fail to start LFSCK for layout!"

	wait_all_targets_blocked layout completed 3

	local repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_dangling/ { print $2 }')
	[ $repaired -ge 32 ] ||
		error "(4) Fail to repair dangling reference: $repaired"

	echo "'stat' should fail because of not repair dangling by default"
	stat $DIR/$tdir/guard > /dev/null 2>&1 && error "(5) stat should fail"

	echo "Trigger layout LFSCK to repair dangling reference"
	$START_LAYOUT -r -o -c -d || error "(6) Fail to start LFSCK for layout!"

	wait_all_targets_blocked layout completed 7

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

	echo "stopall to cleanup object cache"
	stopall > /dev/null
	echo "setupall"
	setupall > /dev/null
}
run_test 14b "LFSCK can repair MDT-object with dangling LOV EA reference (2)"

test_15a() {
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3591"

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

	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0x1611
	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=1
	$LFS setstripe -E 1M -S 256K -c 1 -E -1 -S 512K -c $OSTCOUNT \
		$DIR/$tdir/f1 ||
		error "(0) Fail to create PFL $DIR/$tdir/f1"
	# 'dd' will trigger punch RPC firstly on every OST-objects.
	# So even though some OST-object will not be write by 'dd',
	# as long as it is allocated (may be NOT allocated in pfl_3b)
	# its layout information will be set also.
	dd if=/dev/zero of=$DIR/$tdir/f1 bs=4K count=257
	cancel_lru_locks osc
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0

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
	[ $repaired -ge 3 ] ||
		error "(3) Fail to repair unmatched pair: $repaired"
}
run_test 15a "LFSCK can repair unmatched MDT-object/OST-object pairs (1)"

test_15b() {
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3591"

	echo "#####"
	echo "If the OST-object referenced by the MDT-object back points"
	echo "to other MDT-object that doesn't recognize the OST-object,"
	echo "then the LFSCK should repair it to back point to the right"
	echo "MDT-object (the first one)."
	echo "#####"

	check_mount_and_prep
	mkdir -p $DIR/$tdir/0
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/0
	dd if=/dev/zero of=$DIR/$tdir/0/guard bs=1M count=1
	cancel_lru_locks osc

	echo "Inject failure stub to make the OST-object to back point to"
	echo "other MDT-object"

	local stripes=1
	[ $OSTCOUNT -ge 2 ] && stripes=2

	#define OBD_FAIL_LFSCK_UNMATCHED_PAIR2	0x1612
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0x1612
	dd if=/dev/zero of=$DIR/$tdir/0/f0 bs=1M count=1
	$LFS setstripe -E 1M -S 256K -c $stripes -E 2M -S 512K -c 1 \
		$DIR/$tdir/f1 ||
		error "(0) Fail to create PFL $DIR/$tdir/f1"
	dd if=/dev/zero of=$DIR/$tdir/f1 bs=1M count=2
	cancel_lru_locks osc
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0

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
	[ $repaired -eq 4 ] ||
		error "(3) Fail to repair unmatched pair: $repaired"
}
run_test 15b "LFSCK can repair unmatched MDT-object/OST-object pairs (2)"

test_15c() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	(( $MDS1_VERSION < $(version_code 2.7.55) )) ||
		skip "MDS newer than 2.7.55, LU-6475"
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3591"

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

	wait_all_targets_blocked layout completed 2

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
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3594"

	echo "#####"
	echo "If the OST-object's owner information does not match the owner"
	echo "information stored in the MDT-object, then the LFSCK trust the"
	echo "MDT-object and update the OST-object's owner information."
	echo "#####"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir
	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=1
	cancel_lru_locks osc

	# created but no setattr or write to the file.
	mkdir $DIR/$tdir/d1
	chown $RUNAS_ID:$RUNAS_GID $DIR/$tdir/d1
	$RUNAS createmany -o $DIR/$tdir/d1/o 100 || error "create failed"

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
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3594"

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
	cancel_lru_locks mdc
	cancel_lru_locks osc

	createmany -o $DIR/$tdir/f 1
	cancel_lru_locks mdc
	cancel_lru_locks osc

	$LFS setstripe -E 2M -S 256K -o 0 -E 4M -S 512K -o 0 \
		$DIR/$tdir/f1 ||
		error "(0) Fail to create PFL $DIR/$tdir/f1"
	cancel_lru_locks mdc
	cancel_lru_locks osc
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0

	echo "$DIR/$tdir/f0 and $DIR/$tdir/guard use the same OST-objects"
	echo "$DIR/$tdir/f1 and $DIR/$tdir/guard use the same OST-objects"
	local size=$(ls -l $DIR/$tdir/f0 | awk '{ print $5 }')
	[ $size -eq 1048576 ] ||
		error "(1.1) f0 (wrong) size should be 1048576, but got $size"

	size=$(ls -l $DIR/$tdir/f1 | awk '{ print $5 }')
	[ $size -eq 1048576 ] ||
		error "(1.2) f1 (wrong) size should be 1048576, but got $size"

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
	[ $repaired -eq 2 ] ||
		error "(4) Fail to repair multiple references: $repaired"

	echo "$DIR/$tdir/f0 and $DIR/$tdir/guard should use diff OST-objects"
	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=2 ||
		error "(5) Fail to write f0."
	size=$(ls -l $DIR/$tdir/guard | awk '{ print $5 }')
	[ $size -eq 1048576 ] ||
		error "(6) guard size should be 1048576, but got $size"

	echo "$DIR/$tdir/f1 and $DIR/$tdir/guard should use diff OST-objects"
	dd if=/dev/zero of=$DIR/$tdir/f1 bs=1M count=2 ||
		error "(7) Fail to write f1."
	size=$(ls -l $DIR/$tdir/guard | awk '{ print $5 }')
	[ $size -eq 1048576 ] ||
		error "(8) guard size should be 1048576, but got $size"
}
run_test 17 "LFSCK can repair multiple references"

$LCTL set_param debug=+cache > /dev/null

test_18a() {
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3336"

	echo "#####"
	echo "The target MDT-object is there, but related stripe information"
	echo "is lost or partly lost. The LFSCK should regenerate the missing"
	echo "layout EA entries."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/a1
	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=1M count=2

	local saved_size1=$(ls -il $DIR/$tdir/a1/f1 | awk '{ print $6 }')

	$LFS path2fid $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS mkdir -i 1 $DIR/$tdir/a2
		$LFS setstripe -c 2 -i 1 -S 1M $DIR/$tdir/a2
		dd if=/dev/zero of=$DIR/$tdir/a2/f2 bs=1M count=2
		$LFS path2fid $DIR/$tdir/a2/f2
		$LFS getstripe $DIR/$tdir/a2/f2
	fi

	$LFS setstripe -E 1M -S 1M -o 0 -E -1 -S 1M $DIR/$tdir/f3 ||
		error "(0) Fail to create PFL $DIR/$tdir/f3"

	dd if=/dev/zero of=$DIR/$tdir/f3 bs=1M count=2

	local saved_size2=$(ls -il $DIR/$tdir/f3 | awk '{ print $6 }')

	$LFS path2fid $DIR/$tdir/f3
	$LFS getstripe $DIR/$tdir/f3

	cancel_lru_locks osc

	echo "Inject failure, to make the MDT-object lost its layout EA"
	#define OBD_FAIL_LFSCK_LOST_STRIPE 0x1615
	do_facet mds1 $LCTL set_param fail_loc=0x1615
	chown 1.1 $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0x1615
		chown 1.1 $DIR/$tdir/a2/f2
	fi

	chown 1.1 $DIR/$tdir/f3

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
	[ "$cur_size" != "$saved_size1" ] ||
		error "(1) Expect incorrect file1 size"

	if [ $MDSCOUNT -ge 2 ]; then
		cur_size=$(ls -il $DIR/$tdir/a2/f2 | awk '{ print $6 }')
		[ "$cur_size" != "$saved_size1" ] ||
			error "(2) Expect incorrect file2 size"
	fi

	cur_size=$(ls -il $DIR/$tdir/f3 | awk '{ print $6 }')
	[ "$cur_size" != "$saved_size2" ] ||
		error "(1.2) Expect incorrect file3 size"

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
	[ $repaired -eq 3 ] ||
	error "(6.1) Expect 3 fixed on mds1, but got: $repaired"

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

	$LFS path2fid $DIR/$tdir/f3
	$LFS getstripe $DIR/$tdir/f3

	echo "The file size should be correct after layout LFSCK scanning"
	cur_size=$(ls -il $DIR/$tdir/a1/f1 | awk '{ print $6 }')
	[ "$cur_size" == "$saved_size1" ] ||
		error "(7) Expect file1 size $saved_size1, but got $cur_size"

	if [ $MDSCOUNT -ge 2 ]; then
		cur_size=$(ls -il $DIR/$tdir/a2/f2 | awk '{ print $6 }')
		[ "$cur_size" == "$saved_size1" ] ||
		error "(8) Expect file2 size $saved_size1, but got $cur_size"
	fi

	cur_size=$(ls -il $DIR/$tdir/f3 | awk '{ print $6 }')
	[ "$cur_size" == "$saved_size2" ] ||
		error "(9) Expect file1 size $saved_size2, but got $cur_size"
}
run_test 18a "Find out orphan OST-object and repair it (1)"

test_18b() {
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3336"

	echo "#####"
	echo "The target MDT-object is lost. The LFSCK should re-create the"
	echo "MDT-object under .lustre/lost+found/MDTxxxx. The admin should"
	echo "can move it back to normal namespace manually."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/a1
	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=1M count=2
	local saved_size1=$(ls -il $DIR/$tdir/a1/f1 | awk '{ print $6 }')
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

	$LFS setstripe -E 1M -S 1M -o 0 -E -1 -S 1M $DIR/$tdir/f3 ||
		error "(0) Fail to create PFL $DIR/$tdir/f3"

	dd if=/dev/zero of=$DIR/$tdir/f3 bs=1M count=2

	local saved_size2=$(ls -il $DIR/$tdir/f3 | awk '{ print $6 }')
	local fid3=$($LFS path2fid $DIR/$tdir/f3)
	echo ${fid3}
	$LFS getstripe $DIR/$tdir/f3

	cancel_lru_locks osc

	echo "Inject failure, to simulate the case of missing the MDT-object"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ	0x1616
	do_facet mds1 $LCTL set_param fail_loc=0x1616
	rm -f $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0x1616
		rm -f $DIR/$tdir/a2/f2
	fi

	rm -f $DIR/$tdir/f3

	sync
	sleep 2

	do_facet mds1 $LCTL set_param fail_loc=0
	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0
	fi

	cancel_lru_locks mdc
	cancel_lru_locks osc

	# dryrun mode only check orphans, not repaie
	echo "Trigger layout LFSCK --dryrun to find out orphan OST-object"
	$START_LAYOUT --dryrun -o -r ||
		error "Fail to start layout LFSCK in dryrun mode"
	wait_all_targets_blocked layout completed 2

	local PARAMS=$($SHOW_LAYOUT | awk '/^param/ { print $2 }')
	[ "$PARAMS" == "dryrun,all_targets,orphan" ] ||
		error "Expect 'dryrun,all_targets,orphan', got '$PARAMS'"

	local orphans=$(do_facet mds1 $LCTL get_param -n \
			mdd.$(facet_svc mds1).lfsck_layout |
			awk '/^inconsistent_orphan/ { print $2 }')
	[ $orphans -eq 3 ] ||
		error "Expect 3 found on mds1, but got: $orphans"

	# orphan parents should not be created
	local subdir
	for subdir in $MOUNT/.lustre/lost+found/*; do
		[ ! "$(ls -A $subdir)" ] || error "$subdir not empty"
	done

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
	[ $repaired -eq 3 ] ||
	error "(4.1) Expect 3 fixed on mds1, but got: $repaired"

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

	mv $MOUNT/.lustre/lost+found/MDT0000/${fid3}-R-0 $DIR/$tdir/f3 ||
	error "(5) Fail to move $MOUNT/.lustre/lost+found/MDT0000/${fid3}-R-0"

	$LFS path2fid $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS path2fid $DIR/$tdir/a2/f2
		$LFS getstripe $DIR/$tdir/a2/f2
	fi

	$LFS path2fid $DIR/$tdir/f3
	$LFS getstripe $DIR/$tdir/f3

	echo "The file size should be correct after layout LFSCK scanning"
	local cur_size=$(ls -il $DIR/$tdir/a1/f1 | awk '{ print $6 }')
	[ "$cur_size" == "$saved_size1" ] ||
		error "(7) Expect file1 size $saved_size1, but got $cur_size"

	if [ $MDSCOUNT -ge 2 ]; then
		cur_size=$(ls -il $DIR/$tdir/a2/f2 | awk '{ print $6 }')
		[ "$cur_size" == "$saved_size1" ] ||
		error "(8) Expect file2 size $saved_size1, but got $cur_size"
	fi

	cur_size=$(ls -il $DIR/$tdir/f3 | awk '{ print $6 }')
	[ "$cur_size" == "$saved_size2" ] ||
		error "(9) Expect file1 size $saved_size2, but got $cur_size"
}
run_test 18b "Find out orphan OST-object and repair it (2)"

test_18c() {
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3336"

	echo "#####"
	echo "The target MDT-object is lost, and the OST-object FID is missing."
	echo "The LFSCK should re-create the MDT-object with new FID under the "
	echo "directory .lustre/lost+found/MDTxxxx."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/a1

	echo "Inject failure, to simulate the case of missing parent FID"
	#define OBD_FAIL_LFSCK_NOPFID		0x1617
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0x1617

	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=1M count=2
	$LFS getstripe $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS mkdir -i 1 $DIR/$tdir/a2
		$LFS setstripe -c 1 -i 0 $DIR/$tdir/a2
		dd if=/dev/zero of=$DIR/$tdir/a2/f2 bs=1M count=2
		$LFS getstripe $DIR/$tdir/a2/f2
	fi

	$LFS setstripe -E 1M -S 1M -o 0 -E -1 -S 1M $DIR/$tdir/f3 ||
		error "(0) Fail to create PFL $DIR/$tdir/f3"

	dd if=/dev/zero of=$DIR/$tdir/f3 bs=1M count=2
	$LFS getstripe $DIR/$tdir/f3

	cancel_lru_locks osc
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0

	echo "Inject failure, to simulate the case of missing the MDT-object"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ	0x1616
	do_facet mds1 $LCTL set_param fail_loc=0x1616
	rm -f $DIR/$tdir/a1/f1

	if [ $MDSCOUNT -ge 2 ]; then
		do_facet mds2 $LCTL set_param fail_loc=0x1616
		rm -f $DIR/$tdir/a2/f2
	fi

	rm -f $DIR/$tdir/f3

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
		expected=4
	else
		expected=3
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
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3336"

	echo "#####"
	echo "The target MDT-object layout EA is corrupted, but the right"
	echo "OST-object is still alive as orphan. The layout LFSCK will"
	echo "not create new OST-object to occupy such slot."
	echo "#####"

	check_mount_and_prep
	mkdir $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/a1
	echo "guard" > $DIR/$tdir/a1/f1
	echo "foo" > $DIR/$tdir/a1/f2

	echo "guard" > $DIR/$tdir/a1/f3
	$LFS setstripe -E 1M -S 1M -o 0 -E -1 -S 1M $DIR/$tdir/a1/f4 ||
		error "(0) Fail to create PFL $DIR/$tdir/a1/f4"
	echo "foo" > $DIR/$tdir/a1/f4

	local saved_size1=$(ls -il $DIR/$tdir/a1/f2 | awk '{ print $6 }')
	local saved_size2=$(ls -il $DIR/$tdir/a1/f4 | awk '{ print $6 }')
	$LFS path2fid $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a1/f1
	$LFS path2fid $DIR/$tdir/a1/f2
	$LFS getstripe $DIR/$tdir/a1/f2
	$LFS path2fid $DIR/$tdir/a1/f3
	$LFS getstripe $DIR/$tdir/a1/f3
	$LFS path2fid $DIR/$tdir/a1/f4
	$LFS getstripe $DIR/$tdir/a1/f4
	cancel_lru_locks osc

	echo "Inject failure to make $DIR/$tdir/a1/f1 and $DIR/$tdir/a1/f2"
	echo "to reference the same OST-object (which is f1's OST-obejct)."
	echo "Then drop $DIR/$tdir/a1/f1 and its OST-object, so f2 becomes"
	echo "dangling reference case, but f2's old OST-object is there."

	echo "The failure also makes $DIR/$tdir/a1/f3 and $DIR/$tdir/a1/f4"
	echo "to reference the same OST-object (which is f3's OST-obejct)."
	echo "Then drop $DIR/$tdir/a1/f3 and its OST-object, so f4 becomes"
	echo "dangling reference case, but f4's old OST-object is there."
	echo

	#define OBD_FAIL_LFSCK_CHANGE_STRIPE	0x1618
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1618
	chown 1.1 $DIR/$tdir/a1/f2
	chown 1.1 $DIR/$tdir/a1/f4
	rm -f $DIR/$tdir/a1/f1
	rm -f $DIR/$tdir/a1/f3
	sync
	sleep 2
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	echo "stopall to cleanup object cache"
	stopall > /dev/null
	echo "setupall"
	setupall > /dev/null

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o -c -d || error "(2) Fail to start LFSCK for layout!"

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
	[ $repaired -eq 2 ] ||
		error "(5) Expect 2 orphans have been fixed, but got: $repaired"

	repaired=$(do_facet $SINGLEMDS $LCTL get_param -n \
		   mdd.$(facet_svc $SINGLEMDS).lfsck_layout |
		   awk '/^repaired_dangling/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(6) Expect 0 dangling has been fixed, but got: $repaired"

	echo "The file size should be correct after layout LFSCK scanning"
	local cur_size=$(ls -il $DIR/$tdir/a1/f2 | awk '{ print $6 }')
	[ "$cur_size" == "$saved_size1" ] ||
		error "(7) Expect file2 size $saved_size1, but got $cur_size"

	cur_size=$(ls -il $DIR/$tdir/a1/f4 | awk '{ print $6 }')
	[ "$cur_size" == "$saved_size2" ] ||
		error "(8) Expect file4 size $saved_size2, but got $cur_size"

	echo "The LFSCK should find back the original data."
	cat $DIR/$tdir/a1/f2
	$LFS path2fid $DIR/$tdir/a1/f2
	$LFS getstripe $DIR/$tdir/a1/f2
	cat $DIR/$tdir/a1/f4
	$LFS path2fid $DIR/$tdir/a1/f4
	$LFS getstripe $DIR/$tdir/a1/f4
}
run_test 18d "Find out orphan OST-object and repair it (4)"

test_18e() {
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3336"

	echo "#####"
	echo "The target MDT-object layout EA slot is occpuied by some new"
	echo "created OST-object when repair dangling reference case. Such"
	echo "conflict OST-object has been modified by others. To keep the"
	echo "new data, the LFSCK will create a new file to refernece this"
	echo "old orphan OST-object."
	echo "#####"

	check_mount_and_prep
	mkdir $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/a1
	echo "guard" > $DIR/$tdir/a1/f1
	echo "foo" > $DIR/$tdir/a1/f2

	echo "guard" > $DIR/$tdir/a1/f3
	$LFS setstripe -E 1M -S 1M -o 0 -E -1 -S 1M $DIR/$tdir/a1/f4 ||
		error "(0) Fail to create PFL $DIR/$tdir/a1/f4"
	echo "foo" > $DIR/$tdir/a1/f4

	local saved_size1=$(ls -il $DIR/$tdir/a1/f2 | awk '{ print $6 }')
	local saved_size2=$(ls -il $DIR/$tdir/a1/f4 | awk '{ print $6 }')

	$LFS path2fid $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a1/f1
	$LFS path2fid $DIR/$tdir/a1/f2
	$LFS getstripe $DIR/$tdir/a1/f2
	$LFS path2fid $DIR/$tdir/a1/f3
	$LFS getstripe $DIR/$tdir/a1/f3
	$LFS path2fid $DIR/$tdir/a1/f4
	$LFS getstripe $DIR/$tdir/a1/f4
	cancel_lru_locks osc

	echo "Inject failure to make $DIR/$tdir/a1/f1 and $DIR/$tdir/a1/f2"
	echo "to reference the same OST-object (which is f1's OST-obejct)."
	echo "Then drop $DIR/$tdir/a1/f1 and its OST-object, so f2 becomes"
	echo "dangling reference case, but f2's old OST-object is there."

	echo "Also the failure makes $DIR/$tdir/a1/f3 and $DIR/$tdir/a1/f4"
	echo "to reference the same OST-object (which is f3's OST-obejct)."
	echo "Then drop $DIR/$tdir/a1/f3 and its OST-object, so f4 becomes"
	echo "dangling reference case, but f4's old OST-object is there."
	echo

	#define OBD_FAIL_LFSCK_CHANGE_STRIPE	0x1618
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1618
	chown 1.1 $DIR/$tdir/a1/f2
	chown 1.1 $DIR/$tdir/a1/f4
	rm -f $DIR/$tdir/a1/f1
	rm -f $DIR/$tdir/a1/f3
	sync
	sleep 2
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	echo "stopall to cleanup object cache"
	stopall > /dev/null
	echo "setupall"
	setupall > /dev/null

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

	echo "Write new data to f2/f4 to modify the new created OST-object."
	echo "dummy" >> $DIR/$tdir/a1/f2 || error "write a1/f2 failed"
	echo "dummy" >> $DIR/$tdir/a1/f4 || error "write a1/f4 failed"

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
	[ $repaired -eq 2 ] ||
		error "(6) Expect 2 orphans have been fixed, but got: $repaired"

	echo "There should be stub file under .lustre/lost+found/MDT0000/"
	[ -d $MOUNT/.lustre/lost+found/MDT0000 ] ||
		error "(7) $MOUNT/.lustre/lost+found/MDT0000/ should be there"

	local count=$(ls -l $MOUNT/.lustre/lost+found/MDT0000/*-C-* | wc -l)
	if [ $count -ne 2 ]; then
		ls -l $MOUNT/.lustre/lost+found/MDT0000/*-C-*
		error "(8) Expect 2 stubs under lost+found, but got $count"
	fi

	echo "The stub file should keep the original f2 or f4 data"
	cname=$(find $MOUNT/.lustre/lost+found/MDT0000/ -name *-C-* | head -n 1)
	local cur_size=$(ls -il $cname | awk '{ print $6 }')
	[ "$cur_size" != "$saved_size1" -a "$cur_size" != "$saved_size2" ] &&
		error "(9) Got unexpected $cur_size"

	cat $cname
	$LFS path2fid $cname
	$LFS getstripe $cname

	cname=$(find $MOUNT/.lustre/lost+found/MDT0000/ -name *-C-* | tail -n 1)
	cur_size=$(ls -il $cname | awk '{ print $6 }')
	[ "$cur_size" != "$saved_size1" -a "$cur_size" != "$saved_size2" ] &&
		error "(10) Got unexpected $cur_size"

	cat $cname
	$LFS path2fid $cname
	$LFS getstripe $cname

	echo "The f2/f4 should contains new data."
	cat $DIR/$tdir/a1/f2
	$LFS path2fid $DIR/$tdir/a1/f2
	$LFS getstripe $DIR/$tdir/a1/f2
	cat $DIR/$tdir/a1/f4
	$LFS path2fid $DIR/$tdir/a1/f4
	$LFS getstripe $DIR/$tdir/a1/f4
}
run_test 18e "Find out orphan OST-object and repair it (5)"

test_18f() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return

	echo "#####"
	echo "The target MDT-object is lost. The LFSCK should re-create the"
	echo "MDT-object under .lustre/lost+found/MDTxxxx. If some OST fail"
	echo "to verify some OST-object(s) during the first stage-scanning,"
	echo "the LFSCK should skip orphan OST-objects for such OST. Others"
	echo "should not be affected."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/a1
	$LFS setstripe -c 1 -i 0 $DIR/$tdir/a1
	dd if=/dev/zero of=$DIR/$tdir/a1/guard bs=1M count=2
	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=1M count=2
	$LFS mkdir -i 0 $DIR/$tdir/a2
	$LFS setstripe -c 2 -i 0 -S 1M $DIR/$tdir/a2
	dd if=/dev/zero of=$DIR/$tdir/a2/f2 bs=1M count=2
	$LFS getstripe $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a2/f2

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS mkdir -i 1 $DIR/$tdir/a3
		$LFS setstripe -c 1 -i 0 $DIR/$tdir/a3
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

test_18g() {
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"

	echo "#####"
	echo "The target MDT-object is lost, but related OI mapping is there"
	echo "The LFSCK should recreate the lost MDT-object without affected"
	echo "by the stale OI mapping."
	echo "#####"

	check_mount_and_prep
	$LFS mkdir -i 0 $DIR/$tdir/a1
	$LFS setstripe -c -1 -i 0 -S 1M $DIR/$tdir/a1
	dd if=/dev/zero of=$DIR/$tdir/a1/f1 bs=1M count=$OSTCOUNT
	local fid1=$($LFS path2fid $DIR/$tdir/a1/f1)
	echo ${fid1}
	$LFS getstripe $DIR/$tdir/a1/f1
	cancel_lru_locks osc

	echo "Inject failure to simulate lost MDT-object but keep OI mapping"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ2	0x162e
	do_facet mds1 $LCTL set_param fail_loc=0x162e
	rm -f $DIR/$tdir/a1/f1

	do_facet mds1 $LCTL set_param fail_loc=0
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
	[ $repaired -eq $OSTCOUNT ] ||
		error "(4) Expect $OSTCOUNT fixed, but got: $repaired"

	echo "Move the files from ./lustre/lost+found/MDTxxxx to namespace"
	mv $MOUNT/.lustre/lost+found/MDT0000/${fid1}-R-0 $DIR/$tdir/a1/f1 ||
	error "(5) Fail to move $MOUNT/.lustre/lost+found/MDT0000/${fid1}-R-0"

	$LFS path2fid $DIR/$tdir/a1/f1
	$LFS getstripe $DIR/$tdir/a1/f1
}
run_test 18g "Find out orphan OST-object and repair it (7)"

test_18h() {
	echo "#####"
	echo "The PFL extent crashed. During the first cycle LFSCK scanning,"
	echo "the layout LFSCK will keep the bad PFL file(s) there without"
	echo "scanning its OST-object(s). Then in the second stage scanning,"
	echo "the OST will return related OST-object(s) to the MDT as orphan."
	echo "And then the LFSCK on the MDT can rebuild the PFL extent with"
	echo "the 'orphan(s)' stripe information."
	echo "#####"

	check_mount_and_prep

	$LFS setstripe -E 2M -S 1M -c 1 -E -1 $DIR/$tdir/f0 ||
		error "(0) Fail to create PFL $DIR/$tdir/f0"

	cat $LUSTRE/tests/test-framework.sh > $DIR/$tdir/f0 ||
		error "(1.1) Fail to write $DIR/$tdir/f0"

	dd if=$LUSTRE/tests/test-framework.sh of=$DIR/$tdir/f0 bs=1M seek=2 ||
		error "(1.2) Fail to write $DIR/$tdir/f0"

	cp $DIR/$tdir/f0 $DIR/$tdir/guard

	echo "Inject failure stub to simulate bad PFL extent range"
	#define OBD_FAIL_LFSCK_BAD_PFL_RANGE	0x162f
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x162f

	chown 1.1 $DIR/$tdir/f0

	cancel_lru_locks mdc
	cancel_lru_locks osc
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0

	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=1 &&
		error "(2) Write to bad PFL file should fail"

	echo "Trigger layout LFSCK to find out the bad lmm_oi and fix them"
	$START_LAYOUT -r -o || error "(3) Fail to start LFSCK for layout!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" $LTIME ||
			error "(4.1) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		cur_status=$(do_facet ost${k} $LCTL get_param -n \
			     obdfilter.$(facet_svc ost${k}).lfsck_layout |
			     awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(4.2) OST${k} Expect 'completed', but got '$cur_status'"

	done

	local repaired=$($SHOW_LAYOUT |
			 awk '/^repaired_orphan/ { print $2 }')
	[ $repaired -eq 2 ] ||
		error "(5) Fail to repair crashed PFL range: $repaired"

	echo "Data in $DIR/$tdir/f0 should not be broken"
	diff $DIR/$tdir/f0 $DIR/$tdir/guard ||
		error "(6) Data in $DIR/$tdir/f0 is broken"

	echo "Write should succeed after LFSCK repairing the bad PFL range"
	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=1 ||
		error "(7) Write should succeed after LFSCK"
}
run_test 18h "LFSCK can repair crashed PFL extent range"

$LCTL set_param debug=-cache > /dev/null

test_19a() {
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3951"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param -n \
		obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid 0

	echo "foo1" > $DIR/$tdir/a0
	$LFS setstripe -E 512K -S 512K -o 0 -E -1 -S 1M $DIR/$tdir/a1 ||
		error "(0) Fail to create PFL $DIR/$tdir/a1"
	echo "foo2" > $DIR/$tdir/a1
	echo "guard" > $DIR/$tdir/a2
	cancel_lru_locks osc

	echo "Inject failure, then client will offer wrong parent FID when read"
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param -n \
		obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid 1

	#define OBD_FAIL_LFSCK_INVALID_PFID	0x1619
	$LCTL set_param fail_loc=0x1619

	echo "Read RPC with wrong parent FID should be denied"
	cat $DIR/$tdir/a0 && error "(3.1) Read a0 should be denied!"
	cat $DIR/$tdir/a1 && error "(3.2) Read a1 should be denied!"
	$LCTL set_param fail_loc=0
}
run_test 19a "OST-object inconsistency self detect"

test_19b() {
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-3951"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	echo "Inject failure stub to make the OST-object to back point to"
	echo "non-exist MDT-object"

	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param -n \
		obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid 0

	#define OBD_FAIL_LFSCK_UNMATCHED_PAIR1	0x1611
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0x1611
	echo "foo1" > $DIR/$tdir/f0
	$LFS setstripe -E 1M -S 1M -o 0 -E 4M -S 256K $DIR/$tdir/f1 ||
		error "(0) Fail to create PFL $DIR/$tdir/f1"
	echo "foo2" > $DIR/$tdir/f1
	cancel_lru_locks osc
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0

	do_facet ost1 $LCTL set_param -n \
		obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid 0
	echo "Nothing should be fixed since self detect and repair is disabled"
	local repaired=$(do_facet ost1 $LCTL get_param -n \
			obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid |
			awk '/^repaired/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(1) Expected 0 repaired, but got $repaired"

	echo "Read RPC with right parent FID should be accepted,"
	echo "and cause parent FID on OST to be fixed"

	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param -n \
		obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid 1

	cat $DIR/$tdir/f0 || error "(2.1) Read f0 should not be denied!"
	cat $DIR/$tdir/f1 || error "(2.2) Read f1 should not be denied!"

	repaired=$(do_facet ost1 $LCTL get_param -n \
		obdfilter.${FSNAME}-OST0000.lfsck_verify_pfid |
		awk '/^repaired/ { print $2 }')
	[ $repaired -eq 2 ] ||
		error "(3) Expected 1 repaired, but got $repaired"
}
run_test 19b "OST-object inconsistency self repair"

PATTERN_WITH_HOLE="40000001"
PATTERN_WITHOUT_HOLE="raid0"

test_20a() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-4887"

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

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o || error "(1) Fail to start LFSCK for layout!"

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

	local pattern=$($LFS getstripe -L $name)
	[[ "$pattern" = "$PATTERN_WITHOUT_HOLE" ]] ||
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

	pattern=$($LFS getstripe -L $name)
	[[ "$pattern" = "$PATTERN_WITH_HOLE" ]] ||
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

	pattern=$($LFS getstripe -L $name)
	[[ "$pattern" = "$PATTERN_WITH_HOLE" ]] ||
		error "(7.2) expect pattern flag hole, but got $pattern"

	stripes=$($LFS getstripe -c $name)
	size=$(stat $name | awk '/Size:/ { print $2 }')
	if [ $OSTCOUNT -gt 2 ]; then
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
		[ $stripes -eq 2 ] ||
		error "(7.3.2) expect the stripe count is 2, but got $stripes"

		# stripe1 is dummy
		[ $size -eq $((4096 * (256 + 0))) ] ||
		error "(7.4.2) expect the size $((4096 * 256)), but got $size"

		cat $name > /dev/null &&
			error "(7.5.2) normal read $name should fail"

		failures=$(dd if=$name of=$DIR/$tdir/dump conv=sync,noerror \
			   bs=4096 2>&1 | grep "Input/output error" | wc -l)
		[ $failures -eq 256 ] ||
		error "(7.6.2) expect 256 IO failures, but get $failures"

		bcount=$((256 * 2))
		size=$(stat $DIR/$tdir/dump | awk '/Size:/ { print $2 }')
		[ $size -eq $((4096 * $bcount)) ] ||
		error "(7.7.2) expect the size $((4096 * $bcount)), got $size"

		dd if=/dev/zero of=$name conv=sync,notrunc bs=4096 count=1 \
		seek=256 && error "(7.8.2) write to the LOV EA hole should fail"

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

	pattern=$($LFS getstripe -L $name)
	[[ "$pattern" = "$PATTERN_WITH_HOLE" ]] ||
		error "(8.2) expect pattern flag hole, but got $pattern"

	stripes=$($LFS getstripe -c $name)
	[ $stripes -eq 3 ] ||
		error "(8.3) expect the stripe count is 3, but got $stripes"

	size=$(stat $name | awk '/Size:/ { print $2 }')
	# stripe2 is lost
	[ $size -eq $((4096 * (256 + 256 + 0))) ] ||
		error "(8.4) expect the size $((4096 * 512)), but got $size"

	cat $name > /dev/null &&
		error "(8.5) normal read $name should fail"

	failures=$(dd if=$name of=$DIR/$tdir/dump conv=sync,noerror \
		   bs=4096 2>&1 | grep "Input/output error" | wc -l)
	# stripe2 is dummy
	[ $failures -eq 256 ] ||
		error "(8.6) expect 256 IO failures, but get $failures"

	bcount=$((256 * 3))
	size=$(stat $DIR/$tdir/dump | awk '/Size:/ { print $2 }')
	[ $size -eq $((4096 * $bcount)) ] ||
		error "(8.7) expect the size $((4096 * $bcount)), but got $size"

	dd if=/dev/zero of=$name conv=sync,notrunc bs=4096 count=1 \
		seek=512 && error "(8.8) write to the LOV EA hole should fail"

	chown $RUNAS_ID:$RUNAS_GID $name ||
		error "(8.9) cannot chown on $name"

	touch $name || error "(8.10) cannot touch $name"

	rm -f $name || error "(8.11) cannot unlink $name"
}
run_test 20a "Handle the orphan with dummy LOV EA slot properly"

test_20b() {
	[ $OSTCOUNT -lt 2 ] && skip "needs >= 2 OSTs" && return
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	(( $MDS1_VERSION > $(version_code 2.5.55) )) ||
		skip "MDS older than 2.5.55, LU-4887"

	echo "#####"
	echo "The target MDT-object and some of its OST-object are lost."
	echo "The LFSCK should find out the left OST-objects and re-create"
	echo "the MDT-object under the direcotry .lustre/lost+found/MDTxxxx/"
	echo "with the partial OST-objects (LOV EA hole)."

	echo "New client can access the file with LOV EA hole via normal"
	echo "system tools or commands without crash the system - PFL case."
	echo "#####"

	check_mount_and_prep

	$LFS setstripe -E 2M -S 1M -c 2 -E -1 -S 1M -c 2 $DIR/$tdir/f0 ||
		error "(0) Fail to create PFL file $DIR/$tdir/f0"
	$LFS setstripe -E 2M -S 1M -c 2 -E -1 -S 1M -c 2 $DIR/$tdir/f1 ||
		error "(1) Fail to create PFL file $DIR/$tdir/f1"
	$LFS setstripe -E 2M -S 1M -c 2 -E -1 -S 1M -c 2 $DIR/$tdir/f2 ||
		error "(2) Fail to create PFL file $DIR/$tdir/f2"

	local bcount=$((256 * 3 + 1))

	dd if=/dev/zero of=$DIR/$tdir/f0 bs=4096 count=$bcount
	dd if=/dev/zero of=$DIR/$tdir/f1 bs=4096 count=$bcount
	dd if=/dev/zero of=$DIR/$tdir/f2 bs=4096 count=$bcount

	local fid0=$($LFS path2fid $DIR/$tdir/f0)
	local fid1=$($LFS path2fid $DIR/$tdir/f1)
	local fid2=$($LFS path2fid $DIR/$tdir/f2)

	echo ${fid0}
	$LFS getstripe $DIR/$tdir/f0
	echo ${fid1}
	$LFS getstripe $DIR/$tdir/f1
	echo ${fid2}
	$LFS getstripe $DIR/$tdir/f2

	cancel_lru_locks mdc
	cancel_lru_locks osc

	echo "Inject failure..."
	echo "To simulate f0 lost MDT-object"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ	0x1616
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1616
	rm -f $DIR/$tdir/f0

	echo "To simulate the case of f1 lost MDT-object and "
	echo "the first OST-object in each PFL component"
	#define OBD_FAIL_LFSCK_LOST_SPEOBJ	0x161a
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x161a
	rm -f $DIR/$tdir/f1

	echo "To simulate the case of f2 lost MDT-object and "
	echo "the second OST-object in each PFL component"
	do_facet $SINGLEMDS $LCTL set_param fail_val=1
	rm -f $DIR/$tdir/f2

	sync
	sleep 2
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o || error "(3) Fail to start LFSCK for layout!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" 32 ||
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
	[ $repaired -eq 8 ] ||
		error "(6) Expect 8 fixed on mds1, but got: $repaired"

	#
	# ${fid0}-R-0 is the old f0
	#
	local name="$MOUNT/.lustre/lost+found/MDT0000/${fid0}-R-0"
	echo "Check $name, which is the old f0"

	$LFS getstripe -v $name || error "(7.1) cannot getstripe on $name"

	local pattern=$($LFS getstripe -L -I1 $name)
	[[ "$pattern" = "$PATTERN_WITHOUT_HOLE" ]] ||
		error "(7.2.1) NOT expect pattern flag hole, but got $pattern"

	pattern=$($LFS getstripe -L -I2 $name)
	[[ "$pattern" = "$PATTERN_WITHOUT_HOLE" ]] ||
		error "(7.2.2) NOT expect pattern flag hole, but got $pattern"

	local stripes=$($LFS getstripe -c -I1 $name)
	[ $stripes -eq 2 ] ||
		error "(7.3.1) expect 2 stripes, but got $stripes"

	stripes=$($LFS getstripe -c -I2 $name)
	[ $stripes -eq 2 ] ||
		error "(7.3.2) expect 2 stripes, but got $stripes"

	local e_start=$($LFS getstripe -I1 $name |
			awk '/lcme_extent.e_start:/ { print $2 }')
	[ $e_start -eq 0 ] ||
		error "(7.4.1) expect the COMP1 start at 0, got $e_start"

	local e_end=$($LFS getstripe -I1 $name |
		      awk '/lcme_extent.e_end:/ { print $2 }')
	[ $e_end -eq 2097152 ] ||
		error "(7.4.2) expect the COMP1 end at 2097152, got $e_end"

	e_start=$($LFS getstripe -I2 $name |
		  awk '/lcme_extent.e_start:/ { print $2 }')
	[ $e_start -eq 2097152 ] ||
		error "(7.5.1) expect the COMP2 start at 2097152, got $e_start"

	e_end=$($LFS getstripe -I2 $name |
		awk '/lcme_extent.e_end:/ { print $2 }')
	[ "$e_end" = "EOF" ] ||
		error "(7.5.2) expect the COMP2 end at (EOF), got $e_end"

	local size=$(stat $name | awk '/Size:/ { print $2 }')
	[ $size -eq $((4096 * $bcount)) ] ||
		error "(7.6) expect the size $((4096 * $bcount)), but got $size"

	cat $name > /dev/null || error "(7.7) cannot read $name"

	echo "dummy" >> $name || error "(7.8) cannot write $name"

	chown $RUNAS_ID:$RUNAS_GID $name || error "(7.9) cannot chown on $name"

	touch $name || error "(7.10) cannot touch $name"

	rm -f $name || error "(7.11) cannot unlink $name"

	#
	# ${fid1}-R-0 contains the old f1's second stripe in each COMP
	#
	name="$MOUNT/.lustre/lost+found/MDT0000/${fid1}-R-0"
	echo "Check $name, it contains f1's second OST-object in each COMP"

	$LFS getstripe -v $name || error "(8.1) cannot getstripe on $name"

	pattern=$($LFS getstripe -L -I1 $name)
	[[ "$pattern" = "$PATTERN_WITH_HOLE" ]] ||
		error "(8.2.1) expect pattern flag hole, but got $pattern"

	pattern=$($LFS getstripe -L -I2 $name)
	[[ "$pattern" = "$PATTERN_WITH_HOLE" ]] ||
		error "(8.2.2) expect pattern flag hole, but got $pattern"

	stripes=$($LFS getstripe -c -I1 $name)
	[ $stripes -eq 2 ] ||
		error "(8.3.2) expect 2 stripes, but got $stripes"

	stripes=$($LFS getstripe -c -I2 $name)
	[ $stripes -eq 2 ] ||
		error "(8.3.2) expect 2 stripes, but got $stripes"

	e_start=$($LFS getstripe -I1 $name |
		  awk '/lcme_extent.e_start:/ { print $2 }')
	[ $e_start -eq 0 ] ||
		error "(8.4.1) expect the COMP1 start at 0, got $e_start"

	e_end=$($LFS getstripe -I1 $name |
		awk '/lcme_extent.e_end:/ { print $2 }')
	[ $e_end -eq 2097152 ] ||
		error "(8.4.2) expect the COMP1 end at 2097152, got $e_end"

	e_start=$($LFS getstripe -I2 $name |
		  awk '/lcme_extent.e_start:/ { print $2 }')
	[ $e_start -eq 2097152 ] ||
		error "(8.5.1) expect the COMP2 start at 2097152, got $e_start"

	e_end=$($LFS getstripe -I2 $name |
		awk '/lcme_extent.e_end:/ { print $2 }')
	[ "$e_end" = "EOF" ] ||
		error "(8.5.2) expect the COMP2 end at (EOF), got $e_end"

	size=$(stat $name | awk '/Size:/ { print $2 }')
	[ $size -eq $((4096 * $bcount)) ] ||
		error "(8.6) expect the size $((4096 * $bcount)), but got $size"

	cat $name > /dev/null && error "(8.7) normal read $name should fail"

	local failures=$(dd if=$name of=$DIR/$tdir/dump conv=sync,noerror \
			 bs=4096 2>&1 | grep "Input/output error" | wc -l)

	# The first stripe in each COMP was lost
	[ $failures -eq 512 ] ||
		error "(8.8) expect 512 IO failures, but get $failures"

	size=$(stat $DIR/$tdir/dump | awk '/Size:/ { print $2 }')
	[ $size -eq $((4096 * $bcount)) ] ||
		error "(8.9) expect the size $((4096 * $bcount)), but got $size"

	dd if=/dev/zero of=$name conv=sync,notrunc bs=4096 count=1 &&
		error "(8.10) write to the LOV EA hole should fail"

	dd if=/dev/zero of=$name conv=sync,notrunc bs=4096 count=1 seek=300 ||
		error "(8.11) write to normal stripe should NOT fail"

	echo "foo" >> $name && error "(8.12) append write $name should fail"

	chown $RUNAS_ID:$RUNAS_GID $name || error "(8.13) cannot chown on $name"

	touch $name || error "(8.14) cannot touch $name"

	rm -f $name || error "(8.15) cannot unlink $name"

	#
	# ${fid2}-R-0 contains the old f2's first stripe in each COMP
	#
	name="$MOUNT/.lustre/lost+found/MDT0000/${fid2}-R-0"
	echo "Check $name, it contains f2's first stripe in each COMP"

	$LFS getstripe -v $name || error "(9.1) cannot getstripe on $name"

	pattern=$($LFS getstripe -L -I1 $name)
	[[ "$pattern" = "$PATTERN_WITH_HOLE" ]] ||
		error "(9.2.1) expect pattern flag hole, but got $pattern"

	pattern=$($LFS getstripe -L -I2 $name)
	[[ "$pattern" = "$PATTERN_WITH_HOLE" ]] ||
		error "(9.2.2) expect pattern flag hole, but got $pattern"

	stripes=$($LFS getstripe -c -I1 $name)
	[ $stripes -eq 2 ] ||
		error "(9.3.2) expect 2 stripes, but got $stripes"

	stripes=$($LFS getstripe -c -I2 $name)
	[ $stripes -eq 2 ] ||
		error "(9.3.2) expect 2 stripes, but got $stripes"

	e_start=$($LFS getstripe -I1 $name |
		  awk '/lcme_extent.e_start:/ { print $2 }')
	[ $e_start -eq 0 ] ||
		error "(9.4.1) expect the COMP1 start at 0, got $e_start"

	e_end=$($LFS getstripe -I1 $name |
		awk '/lcme_extent.e_end:/ { print $2 }')
	[ $e_end -eq 2097152 ] ||
		error "(9.4.2) expect the COMP1 end at 2097152, got $e_end"

	e_start=$($LFS getstripe -I2 $name |
		  awk '/lcme_extent.e_start:/ { print $2 }')
	[ $e_start -eq 2097152 ] ||
		error "(9.5.1) expect the COMP2 start at 2097152, got $e_start"

	e_end=$($LFS getstripe -I2 $name |
		awk '/lcme_extent.e_end:/ { print $2 }')
	[ "$e_end" = "EOF" ] ||
		error "(9.5.2) expect the COMP2 end at (EOF), got $e_end"

	size=$(stat $name | awk '/Size:/ { print $2 }')
	# The second stripe in COMP was lost, so we do not know there
	# have ever been some data before. 'stat' will regard it as
	# no data on the lost stripe.
	bcount=$((256 * 3))
	[ $size -eq $((4096 * $bcount)) ] ||
		error "(9.6) expect size $((4096 * $bcount)), but got $size"

	cat $name > /dev/null &&
		error "(9.7) normal read $name should fail"

	failures=$(dd if=$name of=$DIR/$tdir/dump conv=sync,noerror \
		   bs=4096 2>&1 | grep "Input/output error" | wc -l)
	[ $failures -eq 512 ] ||
		error "(9.8) expect 256 IO failures, but get $failures"

	size=$(stat $DIR/$tdir/dump | awk '/Size:/ { print $2 }')
	# The second stripe in COMP was lost, so we do not know there
	# have ever been some data before. Since 'dd' skip failure,
	# it will regard the lost stripe contains data.
	bcount=$((256 * 4))
	[ $size -eq $((4096 * $bcount)) ] ||
		error "(9.9) expect the size $((4096 * $bcount)), but got $size"

	dd if=/dev/zero of=$name conv=sync,notrunc bs=4096 count=1 \
		seek=300 && error "(9.10) write to the LOV EA hole should fail"

	dd if=/dev/zero of=$name conv=sync,notrunc bs=4096 count=1 ||
		error "(9.11) write to normal stripe should NOT fail"

	echo "foo" >> $name &&
		error "(9.12) append write $name should fail"

	chown $RUNAS_ID:$RUNAS_GID $name ||
		error "(9.13) cannot chown on $name"

	touch $name || error "(9.14) cannot touch $name"

	rm -f $name || error "(7.15) cannot unlink $name"
}
run_test 20b "Handle the orphan with dummy LOV EA slot properly - PFL case"

test_21() {
	(( $MDS1_VERSION > $(version_code 2.5.59) )) ||
		skip "MDS older than 2.5.59, LU-4887"

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5511"

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

	wait_all_targets_blocked namespace completed 6

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5511"

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

	wait_all_targets_blocked namespace completed 6

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5512"

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

	wait_all_targets_blocked namespace completed 6

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^dangling_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(7) Fail to repair dangling name entry: $repaired"

	echo "'ls' should fail because not re-create MDT-object by default"
	ls -ail $DIR/$tdir/d0/d1 > /dev/null 2>&1 && error "(8) ls should fail."

	echo "Trigger namespace LFSCK again to repair dangling name entry"
	$START_NAMESPACE -A -r -C ||
		error "(9) Fail to start LFSCK for namespace"

	wait_all_targets_blocked namespace completed 10

	repaired=$($SHOW_NAMESPACE |
		   awk '/^dangling_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(11) Fail to repair dangling name entry: $repaired"

	echo "'ls' should success after namespace LFSCK repairing"
	ls -ail $DIR/$tdir/d0/d1 > /dev/null || error "(12) ls should success."
}
run_test 23a "LFSCK can repair dangling name entry (1)"

test_23b() {
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5512"

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
	$LFS path2fid $DIR/$tdir/d0

	createmany -o $DIR/$tdir/d0/t 10 || error "(1.5) Fail to creatmany"

	echo "dummy" > $DIR/$tdir/d0/f0 || error "(2) Fail to touch on MDT0"
	$LFS path2fid $DIR/$tdir/d0/f0

	echo "dead" > $DIR/$tdir/d0/f1 || error "(3) Fail to touch on MDT0"
	$LFS path2fid $DIR/$tdir/d0/f1

	local SEQ0=$($LFS path2fid $DIR/$tdir/d0/f0 | awk -F':' '{print $1}')
	local SEQ1=$($LFS path2fid $DIR/$tdir/d0/f1 | awk -F':' '{print $1}')

	if [ "$SEQ0" != "$SEQ1" ]; then
		# To guarantee that the f0 and f1 are in the same FID seq
		rm -f $DIR/$tdir/d0/f0 ||
			error "(3.1) Fail to unlink $DIR/$tdir/d0/f0"
		echo "dummy" > $DIR/$tdir/d0/f0 ||
			error "(3.2) Fail to touch on MDT0"
		$LFS path2fid $DIR/$tdir/d0/f0
	fi

	local OID=$($LFS path2fid $DIR/$tdir/d0/f1 | awk -F':' '{print $2}')
	OID=$(printf %d $OID)

	echo "Inject failure stub on MDT0 to simulate dangling name entry"
	#define OBD_FAIL_LFSCK_DANGLING3	0x1621
	do_facet $SINGLEMDS $LCTL set_param fail_val=$OID fail_loc=0x1621
	ln $DIR/$tdir/d0/f0 $DIR/$tdir/d0/foo || error "(4) Fail to hard link"
	do_facet $SINGLEMDS $LCTL set_param fail_val=0 fail_loc=0

	# If there is creation after the dangling injection, it may re-use
	# the just released local object (inode) that is referenced by the
	# dangling name entry. It will fail the dangling injection.
	# So before deleting the target object for the dangling name entry,
	# remove some other objects to avoid the target object being reused
	# by some potential creations. LU-7429
	unlinkmany $DIR/$tdir/d0/t 10 || error "(5.0) Fail to unlinkmany"

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

cleanup_23c() {
	do_facet $SINGLEMDS $LCTL set_param fail_val=0 fail_loc=0
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(10) unexpected status"
	}

	stop_full_debug_logging
}

test_23c() {
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5512"

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

	start_full_debug_logging

	check_mount_and_prep

	$LFS mkdir -i 0 $DIR/$tdir/d0 || error "(1) Fail to mkdir d0 on MDT0"
	parent_fid="$($LFS path2fid $DIR/$tdir/d0)"
	echo "parent_fid=$parent_fid"

	createmany -o $DIR/$tdir/d0/t 10 || error "(1.5) Fail to creatmany"

	echo "dummy" > $DIR/$tdir/d0/f0 || error "(2) Fail to touch on MDT0"
	f0_fid="$($LFS path2fid $DIR/$tdir/d0/f0)"
	echo "f0_fid=$f0_fid"

	echo "dead" > $DIR/$tdir/d0/f1 || error "(3) Fail to touch on MDT0"
	f1_fid="$($LFS path2fid $DIR/$tdir/d0/f1)"
	echo "f1_fid=$f1_fid"

	if [ "${fid_f0/:.*/}" != "${fid_f1/:.*/}" ]; then
		# To guarantee that the f0 and f1 are in the same FID seq
		rm -f $DIR/$tdir/d0/f0 ||
			error "(3.1) Fail to unlink $DIR/$tdir/d0/f0"
		echo "dummy" > $DIR/$tdir/d0/f0 ||
			error "(3.2) Fail to touch on MDT0"
		f0_fid="$($LFS path2fid $DIR/$tdir/d0/f0)"
		echo "f0_fid=$f0_fid (replaced)"
	fi

	local oid=$(awk -F':' '{ printf $2 }' <<< $f1_fid)

	echo "Inject failure stub on MDT0 to simulate dangling name entry"
	#define OBD_FAIL_LFSCK_DANGLING3	0x1621
	do_facet $SINGLEMDS $LCTL set_param fail_val=$oid fail_loc=0x1621
	ln $DIR/$tdir/d0/f0 $DIR/$tdir/d0/foo || error "(4) Fail to hard link"
	do_facet $SINGLEMDS $LCTL set_param fail_val=0 fail_loc=0

	# If there is creation after the dangling injection, it may re-use
	# the just released local object (inode) that is referenced by the
	# dangling name entry. It will fail the dangling injection.
	# So before deleting the target object for the dangling name entry,
	# remove some other objects to avoid the target object being reused
	# by some potential creations. LU-7429
	unlinkmany $DIR/$tdir/d0/t 10 || error "(5.0) Fail to unlinkmany"

	rm -f $DIR/$tdir/d0/f1 || error "(5) Fail to unlink $DIR/$tdir/d0/f1"

	echo "'ls' should fail because of dangling name entry"
	ls -ail $DIR/$tdir/d0/foo > /dev/null 2>&1 &&
		error "(6) ls should fail."

	#define OBD_FAIL_LFSCK_DELAY3		0x1602
	do_facet $SINGLEMDS $LCTL set_param fail_val=10 fail_loc=0x1602

	echo "Trigger namespace LFSCK to find out dangling name entry"
	$START_NAMESPACE -r -C ||
		error "(7) Fail to start LFSCK for namespace"

	wait_update_facet client "stat -c%s $DIR/$tdir/d0/foo" "0" $LTIME || {
		# While unexpected by the test, it is valid for LFSCK to repair
		# the link to the original object before any data is written.
		local size=$(stat -c %s $DIR/$tdir/d0/foo)

		if [ "$size" = "6" -a "$(<$DIR/$tdir/d0/foo)" = "dummy" ]; then
			log "LFSCK repaired file prematurely"
			cleanup_23c
			return 0
		fi

		stat $DIR/$tdir/d0/foo
		$SHOW_NAMESPACE
		error "(8) unexpected size"
	}

	echo "data" >> $DIR/$tdir/d0/foo || error "(9) Fail to write"
	cancel_lru_locks osc

	cleanup_23c

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5513"

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
	if [ $mds1_FSTYPE != ldiskfs ]; then
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

	wait_all_targets_blocked namespace completed 8

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
	[[ $mds1_FSTYPE == ldiskfs ]] || skip "only ldiskfs fixes dirent type"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5515"

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
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5516"

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

	ls -ail $DIR/$tdir/d0/foo > /dev/null 2>&1 &&
		error "(5) 'ls' should fail"

	echo "Trigger namespace LFSCK to repair the missing remote name entry"
	$START_NAMESPACE -r -A ||
		error "(6) Fail to start LFSCK for namespace"

	wait_all_targets_blocked namespace completed 7

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5516"

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

	ls -ail $DIR/$tdir/d0/foo > /dev/null 2>&1 &&
		error "(4) 'ls' should fail"

	echo "Trigger namespace LFSCK to repair the missing remote name entry"
	$START_NAMESPACE -r -A ||
		error "(5) Fail to start LFSCK for namespace"

	wait_all_targets_blocked namespace completed 6

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
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5516"

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
	ls -ail $DIR/$tdir/d0 > /dev/null 2>&1 && error "(6) 'ls' should fail"

	echo "Trigger namespace LFSCK to repair the lost parent"
	$START_NAMESPACE -r -A ||
		error "(6) Fail to start LFSCK for namespace"

	wait_all_targets_blocked namespace completed 7

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5516"

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
	ls -ail $DIR/$tdir/d0 > /dev/null 2>&1 && error "(5) 'ls' should fail"

	echo "Trigger namespace LFSCK to repair the missing remote name entry"
	$START_NAMESPACE -r -A ||
		error "(6) Fail to start LFSCK for namespace"

	wait_all_targets_blocked namespace completed 7

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5506"

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

	wait_all_targets_blocked namespace completed 9

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
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5517"

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

	wait_all_targets_blocked namespace completed 6

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^nlinks_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(7) Fail to repair nlink count: $repaired"

	cancel_lru_locks mdc
	count=$(stat --format=%h $DIR/$tdir/d0/foo)
	[ $count -eq 2 ] || error "(8) Fail to repair nlink count: $count"
}
# Disable 29a, we only allow nlink to be updated if the known linkEA
# entries is larger than nlink count.
#
#run_test 29a "LFSCK can repair bad nlink count (1)"

test_29b() {
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5517"

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

	wait_all_targets_blocked namespace completed 6

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^nlinks_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(7) Fail to repair nlink count: $repaired"

	cancel_lru_locks mdc
	count=$(stat --format=%h $DIR/$tdir/d0/foo)
	[ $count -eq 2 ] || error "(8) Fail to repair nlink count: $count"
}
run_test 29b "LFSCK can repair bad nlink count (2)"

test_29c()
{
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5517"

	echo "#####"
	echo "The namespace LFSCK will create many hard links to the target"
	echo "file as to exceed the linkEA size limitation. Under such case"
	echo "the linkEA will be marked as overflow that will prevent the"
	echo "target file to be migrated. Then remove some hard links to"
	echo "make the left hard links to be held within the linkEA size"
	echo "limitation. But before the namespace LFSCK adding all the"
	echo "missed linkEA entries back, the overflow mark (timestamp)"
	echo "will not be cleared."
	echo "#####"

	check_mount_and_prep

	mkdir -p $DIR/$tdir/guard || error "(0.1) Fail to mkdir"
	$LFS mkdir -i $((MDSCOUNT - 1)) $DIR/$tdir/foo ||
		error "(0.2) Fail to mkdir"
	touch $DIR/$tdir/guard/f0 || error "(1) Fail to create"
	local oldfid=$($LFS path2fid $DIR/$tdir/guard/f0)

	# define MAX_LINKEA_SIZE        4096
	# sizeof(link_ea_header) = 24
	# sizeof(link_ea_entry) = 18
	# nlink_min=$(((MAX_LINKEA_SIZE - sizeof(link_ea_header)) /
	#	      (sizeof(link_ea_entry) + name_length))
	# If the average name length is 12 bytes, then 150 hard links
	# is totally enough to overflow the linkEA
	echo "Create 150 hard links should succeed although the linkEA overflow"
	createmany -l $DIR/$tdir/guard/f0 $DIR/$tdir/foo/ttttttttttt 150 ||
		error "(2) Fail to hard link"

	cancel_lru_locks mdc
	if [ $MDSCOUNT -ge 2 ]; then
		$LFS migrate -m 1 $DIR/$tdir/guard 2>/dev/null &&
			error "(3.1) Migrate should fail"

		echo "The object with linkEA overflow should NOT be migrated"
		local newfid=$($LFS path2fid $DIR/$tdir/guard/f0)
		[ "$newfid" == "$oldfid" ] ||
			error "(3.2) Migrate should fail: $newfid != $oldfid"
	fi

	# Remove 100 hard links, then the linkEA should have space
	# to hold the missed linkEA entries.
	echo "Remove 100 hard links to save space for the missed linkEA entries"
	unlinkmany $DIR/$tdir/foo/ttttttttttt 100 || error "(4) Fail to unlink"

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS migrate -m 1 $DIR/$tdir/guard 2>/dev/null &&
			error "(5.1) Migrate should fail"

		# The overflow timestamp is still there, so migration will fail.
		local newfid=$($LFS path2fid $DIR/$tdir/guard/f0)
		[ "$newfid" == "$oldfid" ] ||
			error "(5.2) Migrate should fail: $newfid != $oldfid"
	fi

	# sleep 3 seconds to guarantee that the overflow is recognized
	sleep 3

	echo "Trigger namespace LFSCK to clear the overflow timestamp"
	$START_NAMESPACE -r -A ||
		error "(6) Fail to start LFSCK for namespace"

	wait_all_targets_blocked namespace completed 7

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^linkea_overflow_cleared/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(8) Fail to clear linkea overflow: $repaired"

	repaired=$($SHOW_NAMESPACE |
		   awk '/^nlinks_repaired/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(9) Unexpected nlink repaired: $repaired"

	if [ $MDSCOUNT -ge 2 ]; then
		$LFS migrate -m 1 $DIR/$tdir/guard 2>/dev/null ||
			error "(10.1) Migrate failure"

		# Migration should succeed after clear the overflow timestamp.
		local newfid=$($LFS path2fid $DIR/$tdir/guard/f0)
		[ "$newfid" != "$oldfid" ] ||
			error "(10.2) Migrate should succeed"

		ls -l $DIR/$tdir/foo > /dev/null ||
			error "(11) 'ls' failed after migration"
	fi

	rm -f $DIR/$tdir/guard/f0 || error "(12) Fail to unlink f0"
	rm -rf $DIR/$tdir/foo || error "(13) Fail to rmdir foo"
}
run_test 29c "verify linkEA size limitation"

test_30() {
	[[ $mds1_FSTYPE == ldiskfs ]] || skip "only ldiskfs has lost+found"
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5518"

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

	local pfid=$($LFS path2fid $DIR/$tdir/foo)
	local cfid=$($LFS path2fid $DIR/$tdir/foo/d0)

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

	wait_all_targets_blocked namespace completed 15

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^local_lost_found_moved/ { print $2 }')
	[ $repaired -ge 4 ] ||
		error "(16) Fail to recover backend orphans: $repaired"

	mount_client $MOUNT || error "(17) Fail to start client!"

	stat $DIR/$tdir/foo/f0 || error "(18) f0 is not recovered"

	ls -ail $MOUNT/.lustre/lost+found/

	echo "d0 should become orphan under .lustre/lost+found/MDT0000/"
	[ -d $MOUNT/.lustre/lost+found/MDT0000 ] ||
		error "(19) $MOUNT/.lustre/lost+found/MDT0000/ should be there"

	ls -ail $MOUNT/.lustre/lost+found/MDT0000/

	local cname=$MOUNT/.lustre/lost+found/MDT0000/${cfid}-${pfid}-D-0
	[ ! -z "$cname" ] || error "(20) d0 is not recovered"

	stat ${cname}/d1 || error "(21) d1 is not recovered"
	stat ${cname}/f1 || error "(22) f1 is not recovered"
}
run_test 30 "LFSCK can recover the orphans from backend /lost+found"

test_31a() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5519"

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

	wait_all_targets_blocked namespace completed 4

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^name_hash_repaired/ { print $2 }')
	[ $repaired -ge 1 ] ||
		error "(5) Fail to repair bad name hash: $repaired"

	local rc=$($LFS find -H badtype $DIR/$tdir/striped_dir | wc -l)
	[ $rc -ge 1 ] ||
		error "Fail to find flag bad type: $rc"

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5519"

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
	createmany -d $DIR/$tdir/striped_dir/d $((MDSCOUNT * 5)) ||
		error "(2) Fail to create file under striped directory"
	$LCTL set_param fail_loc=0 fail_val=0

	echo "Trigger namespace LFSCK to repair bad name hash"
	$START_NAMESPACE -r -A ||
		error "(3) Fail to start LFSCK for namespace"

	wait_all_targets_blocked namespace completed 4

	local repaired=$(do_facet mds2 $LCTL get_param -n \
			 mdd.$(facet_svc mds2).lfsck_namespace |
			 awk '/^name_hash_repaired/ { print $2 }')
	echo "repaired $repaired name entries with bad hash"
	[ $repaired -ge 1 ] ||
		error "(5) Fail to repair bad name hash: $repaired"

	umount_client $MOUNT || error "(6) umount failed"
	mount_client $MOUNT || error "(7) mount failed"

	for ((i = 0; i < $((MDSCOUNT * 5)); i++)); do
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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5519"

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

	wait_all_targets_blocked namespace completed 3

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^striped_dirs_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(4) Fail to re-generate master LMV EA: $repaired"

	local rc=$($LFS find -H lostlmv $DIR/$tdir/striped_dir | wc -l)
	[ $rc -eq 1 ] || error "Fail to find flag lost LMV: $rc"

	umount_client $MOUNT || error "(5) umount failed"
	mount_client $MOUNT || error "(6) mount failed"

	local empty=$(ls $DIR/$tdir/striped_dir/)
	[ -z "$empty" ] || error "(7) The master LMV EA is not repaired: $empty"

	rmdir $DIR/$tdir/striped_dir ||
		error "(8) Fail to remove the striped directory after LFSCK"
}
run_test 31c "Re-generate the lost master LMV EA for striped directory"

test_31d() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5519"

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

	wait_all_targets_blocked namespace completed 6

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5519"

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

	wait_all_targets_blocked namespace completed 3

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^striped_shards_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(4) Fail to re-generate slave LMV EA: $repaired"

	rmdir $DIR/$tdir/striped_dir ||
		error "(5) Fail to remove the striped directory after LFSCK"
}
run_test 31e "Re-generate the lost slave LMV EA for striped directory (1)"

test_31f() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5519"

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

	wait_all_targets_blocked namespace completed 3

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5519"

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

	wait_all_targets_blocked namespace completed 3

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	(( $MDS1_VERSION > $(version_code 2.6.50) )) ||
		skip "MDS older than 2.6.50, LU-5519"

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

	wait_all_targets_blocked namespace completed 3

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

test_32a()
{
	lfsck_prep 5 5
	umount_client $MOUNT

	#define OBD_FAIL_LFSCK_ENGINE_DELAY	0x162d
	do_facet $SINGLEMDS $LCTL set_param fail_val=3 fail_loc=0x162d
	$START_LAYOUT -r || error "(1) Fail to start LFSCK for layout!"

	local STATUS=$($SHOW_LAYOUT | awk '/^status/ { print $2 }')
	[ "$STATUS" == "scanning-phase1" ] ||
		error "(2) Expect 'scanning-phase1', but got '$STATUS'"

	echo "stop ost1"
	stop ost1 > /dev/null || error "(3) Fail to stop OST1!"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	sleep 4

	echo "stop LFSCK"
	$STOP_LFSCK || error "(4) Fail to stop LFSCK!"

	start ost1 $(ostdevname 1) $MOUNT_OPTS_NOSCRUB > /dev/null ||
		error "(5) Fail to start ost1"
}
run_test 32a "stop LFSCK when some OST failed"

test_32b()
{
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	lfsck_prep 5 5
	$LFS mkdir -i 1 $DIR/$tdir/dp ||
		error "(1) Fail to create $DIR/$tdir/dp"
	$LFS mkdir -i 0 -c $MDSCOUNT $DIR/$tdir/dp/dc1 ||
		error "(2) Fail to create $DIR/$tdir/dp/dc1"
	$LFS mkdir -i 0 -c $MDSCOUNT $DIR/$tdir/dp/dc2 ||
		error "(3) Fail to create $DIR/$tdir/dp/dc2"
	umount_client $MOUNT

	#define OBD_FAIL_LFSCK_ENGINE_DELAY	0x162d
	do_facet $SINGLEMDS $LCTL set_param fail_val=3 fail_loc=0x162d
	$START_NAMESPACE -r -A || error "(4) Fail to start LFSCK for namespace!"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "scanning-phase1" 32 || {
		$SHOW_NAMESPACE
		error "(5) unexpected status"
	}

	echo "stop mds2"
	stop mds2 > /dev/null || error "(6) Fail to stop MDT2!"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0 fail_val=0
	sleep 4

	echo "stop LFSCK"
	$STOP_LFSCK || error "(7) Fail to stop LFSCK!"

	start mds2 $(mdsdevname 2) $MOUNT_OPTS_NOSCRUB > /dev/null ||
		error "(8) Fail to start MDT2"
}
run_test 32b "stop LFSCK when some MDT failed"

test_33()
{
	lfsck_prep 5 5

	$START_LAYOUT --dryrun -o -r ||
		error "(1) Fail to start layout LFSCK"
	wait_all_targets_blocked layout completed 2

	local PARAMS=$($SHOW_LAYOUT | awk '/^param/ { print $2 }')
	[ "$PARAMS" == "dryrun,all_targets,orphan" ] ||
		error "(3) Expect 'dryrun,all_targets,orphan', got '$PARAMS'"

	$START_NAMESPACE -e abort -A -r ||
		error "(4) Fail to start namespace LFSCK"
	wait_all_targets_blocked namespace completed 5

	PARAMS=$($SHOW_NAMESPACE | awk '/^param/ { print $2 }')
	[ "$PARAMS" == "failout,all_targets" ] ||
		error "(6) Expect 'failout,all_targets', got '$PARAMS'"
}
run_test 33 "check LFSCK paramters"

test_34()
{
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	[ "$mds1_FSTYPE" != zfs ] && skip "Only valid for ZFS backend"

	lfsck_prep 1 1

	#define OBD_FAIL_LFSCK_NO_AGENTOBJ	0x1630
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x1630
	$LFS mkdir -i 1 $DIR/$tdir/dummy ||
		error "(1) Fail to create $DIR/$tdir/dummy"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	$START_NAMESPACE -r || error "(2) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(3) unexpected status"
	}

	local repaired=$($SHOW_NAMESPACE |
			 awk '/^dirent_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(4) Fail to repair the lost agent object: $repaired"

	$START_NAMESPACE -r || error "(5) Fail to start LFSCK for namespace!"
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_NAMESPACE
		error "(6) unexpected status"
	}

	repaired=$($SHOW_NAMESPACE | awk '/^dirent_repaired/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(7) Unexpected repairing: $repaired"
}
run_test 34 "LFSCK can rebuild the lost agent object"

test_35()
{
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	lfsck_prep 1 1

	#define OBD_FAIL_LFSCK_NO_AGENTENT	0x1631
	do_facet mds2 $LCTL set_param fail_loc=0x1631
	$LFS mkdir -i 1 $DIR/$tdir/dummy ||
		error "(1) Fail to create $DIR/$tdir/dummy"

	sync; sleep 3
	do_facet mds2 $LCTL set_param fail_loc=0
	$START_NAMESPACE -A -r || error "(2) Fail to start LFSCK for namespace!"
	wait_update_facet mds2 "$LCTL get_param -n \
		mdd.$(facet_svc mds2).lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" $LTIME ||
		error "(3) MDS${k} is not the expected 'completed'"

	local repaired=$(do_facet mds2 $LCTL get_param -n \
			 mdd.$(facet_svc mds2).lfsck_namespace |
			 awk '/^agent_entries_repaired/ { print $2 }')
	[ $repaired -eq 1 ] ||
		error "(4) Fail to repair the lost agent entry: $repaired"

	echo "stopall to cleanup object cache"
	stopall > /dev/null
	echo "setupall"
	setupall > /dev/null

	$START_NAMESPACE -A -r || error "(5) Fail to start LFSCK for namespace!"
	wait_update_facet mds2 "$LCTL get_param -n \
		mdd.$(facet_svc mds2).lfsck_namespace |
		awk '/^status/ { print \\\$2 }'" "completed" $LTIME ||
		error "(6) MDS${k} is not the expected 'completed'"

	repaired=$(do_facet mds2 $LCTL get_param -n \
		   mdd.$(facet_svc mds2).lfsck_namespace |
		   awk '/^agent_entries_repaired/ { print $2 }')
	[ $repaired -eq 0 ] ||
		error "(7) Unexpected repairing: $repaired"
}
run_test 35 "LFSCK can rebuild the lost agent entry"

test_36a() {
	[ $OSTCOUNT -lt 3 ] && skip "needs >= 3 OSTs" && return

	echo "#####"
	echo "The target MDT-object's LOV EA corrupted as to lose one of the "
	echo "mirrors information. The layout LFSCK should rebuild the LOV EA "
	echo "with the PFID EA of related OST-object(s) belong to the mirror."
	echo "#####"

	check_mount_and_prep

	lfs df $DIR
	lfs df -i $DIR
	lctl get_param osc.*.*grant*
	stack_trap "lfs df $DIR; lfs df -i $DIR; lctl get_param osc.*.*grant*"

	$LFS setstripe -N -E 1M -o 0,1 -E -1 -o 2 -N -E 2M -o 1,2 -E -1 -o 0 \
		-N -E 3M -o 2,0 -E -1 -o 1 $DIR/$tdir/f0 ||
		error "(0) Fail to create mirror file $DIR/$tdir/f0"
	$LFS setstripe -N -E 1M -o 0,1 -E -1 -o 2 -N -E 2M -o 1,2 -E -1 -o 0 \
		-N -E 3M -o 2,0 -E -1 -o 1 $DIR/$tdir/f1 ||
		error "(1) Fail to create mirror file $DIR/$tdir/f1"
	$LFS setstripe -N -E 1M -o 0,1 -E -1 -o 2 -N -E 2M -o 1,2 -E -1 -o 0 \
		-N -E 3M -o 2,0 -E -1 -o 1 $DIR/$tdir/f2 ||
		error "(2) Fail to create mirror file $DIR/$tdir/f2"

	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=4 ||
		error "(3) Fail to write $DIR/$tdir/f0"
	dd if=/dev/zero of=$DIR/$tdir/f1 bs=1M count=4 ||
		error "(4) Fail to write $DIR/$tdir/f1"
	dd if=/dev/zero of=$DIR/$tdir/f2 bs=1M count=4 ||
		error "(5) Fail to write $DIR/$tdir/f2"

	$LFS mirror resync $DIR/$tdir/f0 ||
		error "(6) Fail to resync $DIR/$tdir/f0"
	$LFS mirror resync $DIR/$tdir/f1 ||
		error "(7) Fail to resync $DIR/$tdir/f1"
	$LFS mirror resync $DIR/$tdir/f2 ||
		error "(8) Fail to resync $DIR/$tdir/f2"

	cancel_lru_locks mdc
	cancel_lru_locks osc

	$LFS getstripe $DIR/$tdir/f0 ||
		error "(9) Fail to getstripe for $DIR/$tdir/f0"
	$LFS getstripe $DIR/$tdir/f1 ||
		error "(10) Fail to getstripe for $DIR/$tdir/f1"
	$LFS getstripe $DIR/$tdir/f2 ||
		error "(11) Fail to getstripe for $DIR/$tdir/f2"

	echo "Inject failure, to simulate the case of missing one mirror in LOV"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ	0x1616
	do_facet mds1 $LCTL set_param fail_loc=0x1616

	$LFS mirror split --mirror-id 1 -d $DIR/$tdir/f0 ||
		error "(12) Fail to split 1st mirror from $DIR/$tdir/f0"
	$LFS mirror split --mirror-id 2 -d $DIR/$tdir/f1 ||
		error "(13) Fail to split 2nd mirror from $DIR/$tdir/f1"
	$LFS mirror split --mirror-id 3 -d $DIR/$tdir/f2 ||
		error "(14) Fail to split 3rd mirror from $DIR/$tdir/f2"

	sync
	sleep 2
	do_facet mds1 $LCTL set_param fail_loc=0

	$LFS getstripe $DIR/$tdir/f0 | grep "lcme_mirror_id:.*1" &&
		error "(15) The 1st of mirror is not destroyed"
	$LFS getstripe $DIR/$tdir/f1 | grep "lcme_mirror_id:.*2" &&
		error "(16) The 2nd of mirror is not destroyed"
	$LFS getstripe $DIR/$tdir/f2 | grep "lcme_mirror_id:.*3" &&
		error "(17) The 3rd of mirror is not destroyed"

	local mirrors

	mirrors=$($LFS getstripe -N $DIR/$tdir/f0)
	[ $mirrors -eq 2 ] || error "(18) $DIR/$tdir/f0 has $mirrors mirrors"
	mirrors=$($LFS getstripe -N $DIR/$tdir/f1)
	[ $mirrors -eq 2 ] || error "(19) $DIR/$tdir/f1 has $mirrors mirrors"
	mirrors=$($LFS getstripe -N $DIR/$tdir/f2)
	[ $mirrors -eq 2 ] || error "(20) $DIR/$tdir/f2 has $mirrors mirrors"

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o || error "(21) Fail to start LFSCK for layout!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" 32 ||
			error "(22) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		local cur_status=$(do_facet ost${k} $LCTL get_param -n \
				obdfilter.$(facet_svc ost${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(23) OST${k} Expect 'completed', but got '$cur_status'"
	done

	local repaired=$(do_facet mds1 $LCTL get_param -n \
			 mdd.$(facet_svc mds1).lfsck_layout |
			 awk '/^repaired_orphan/ { print $2 }')
	[ $repaired -eq 9 ] ||
		error "(24) Expect 9 fixed on mds1, but got: $repaired"

	mirrors=$($LFS getstripe -N $DIR/$tdir/f0)
	[ $mirrors -eq 3 ] || error "(25) $DIR/$tdir/f0 has $mirrors mirrors"
	mirrors=$($LFS getstripe -N $DIR/$tdir/f1)
	[ $mirrors -eq 3 ] || error "(26) $DIR/$tdir/f1 has $mirrors mirrors"
	mirrors=$($LFS getstripe -N $DIR/$tdir/f2)
	[ $mirrors -eq 3 ] || error "(27) $DIR/$tdir/f2 has $mirrors mirrors"

	$LFS getstripe $DIR/$tdir/f0 | grep "lcme_mirror_id:.*1" || {
		$LFS getstripe $DIR/$tdir/f0
		error "(28) The 1st of mirror is not recovered"
	}

	$LFS getstripe $DIR/$tdir/f1 | grep "lcme_mirror_id:.*2" || {
		$LFS getstripe $DIR/$tdir/f1
		error "(29) The 2nd of mirror is not recovered"
	}

	$LFS getstripe $DIR/$tdir/f2 | grep "lcme_mirror_id:.*3" || {
		$LFS getstripe $DIR/$tdir/f2
		error "(30) The 3rd of mirror is not recovered"
	}
}
run_test 36a "rebuild LOV EA for mirrored file (1)"

test_36b() {
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	[ $OSTCOUNT -lt 3 ] && skip "needs >= 3 OSTs" && return

	echo "#####"
	echo "The mirrored file lost its MDT-object, but relatd OST-objects "
	echo "are still there. The layout LFSCK should rebuild the LOV EA "
	echo "with the PFID EA of related OST-object(s) belong to the file. "
	echo "#####"

	check_mount_and_prep

	$LFS setstripe -N -E 1M -o 0,1 -E -1 -o 2 -N -E 2M -o 1,2 -E -1 -o 0 \
		-N -E 3M -o 2,0 -E -1 -o 1 $DIR/$tdir/f0 ||
		error "(0) Fail to create mirror file $DIR/$tdir/f0"

	local fid=$($LFS path2fid $DIR/$tdir/f0)

	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=4 ||
		error "(1) Fail to write $DIR/$tdir/f0"
	$LFS mirror resync $DIR/$tdir/f0 ||
		error "(2) Fail to resync $DIR/$tdir/f0"

	cancel_lru_locks mdc
	cancel_lru_locks osc

	$LFS getstripe $DIR/$tdir/f0 ||
		error "(3) Fail to getstripe for $DIR/$tdir/f0"

	echo "Inject failure, to simulate the case of missing the MDT-object"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ	0x1616
	do_facet mds1 $LCTL set_param fail_loc=0x1616
	rm -f $DIR/$tdir/f0 || error "(4) Fail to remove $DIR/$tdir/f0"

	sync
	sleep 2
	do_facet mds1 $LCTL set_param fail_loc=0

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o || error "(5) Fail to start LFSCK for layout!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" 32 ||
			error "(6) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		local cur_status=$(do_facet ost${k} $LCTL get_param -n \
				obdfilter.$(facet_svc ost${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(7) OST${k} Expect 'completed', but got '$cur_status'"
	done

	local count=$(do_facet mds1 $LCTL get_param -n \
		      mdd.$(facet_svc mds1).lfsck_layout |
		      awk '/^repaired_orphan/ { print $2 }')
	[ $count -eq 9 ] || error "(8) Expect 9 fixed on mds1, but got: $count"

	local name=$MOUNT/.lustre/lost+found/MDT0000/${fid}-R-0
	count=$($LFS getstripe --mirror-count $name)
	[ $count -eq 3 ] || error "(9) $DIR/$tdir/f0 has $count mirrors"

	count=$($LFS getstripe --component-count $name)
	[ $count -eq 6 ] || error "(10) $DIR/$tdir/f0 has $count components"

	$LFS getstripe $name | grep "lcme_mirror_id:.*1" || {
		$LFS getstripe $name
		error "(11) The 1st of mirror is not recovered"
	}

	$LFS getstripe $name | grep "lcme_mirror_id:.*2" || {
		$LFS getstripe $name
		error "(12) The 2nd of mirror is not recovered"
	}

	$LFS getstripe $name | grep "lcme_mirror_id:.*3" || {
		$LFS getstripe $name
		error "(13) The 3rd of mirror is not recovered"
	}
}
run_test 36b "rebuild LOV EA for mirrored file (2)"

test_36c() {
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"
	[ $OSTCOUNT -lt 3 ] && skip "needs >= 3 OSTs" && return

	echo "#####"
	echo "The mirrored file has been modified, not resynced yet, then "
	echo "lost its MDT-object, but relatd OST-objects are still there. "
	echo "The layout LFSCK should rebuild the LOV EA and relatd status "
	echo "with the PFID EA of related OST-object(s) belong to the file. "
	echo "#####"

	check_mount_and_prep

	$LFS setstripe -N -E 1M -o 0,1 -E -1 -o 2 -N -E 2M -o 1,2 -E -1 -o 0 \
		$DIR/$tdir/f0 ||
		error "(0) Fail to create mirror file $DIR/$tdir/f0"

	local fid=$($LFS path2fid $DIR/$tdir/f0)

	# The 1st dd && resync makes all related OST-objects have been written
	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=4 ||
		error "(1.1) Fail to write $DIR/$tdir/f0"
	$LFS mirror resync $DIR/$tdir/f0 ||
		error "(1.2) Fail to resync $DIR/$tdir/f0"
	# The 2nd dd makes one mirror to be stale
	dd if=/dev/zero of=$DIR/$tdir/f0 bs=1M count=4 ||
		error "(1.3) Fail to write $DIR/$tdir/f0"

	cancel_lru_locks mdc
	cancel_lru_locks osc

	$LFS getstripe $DIR/$tdir/f0 ||
		error "(2) Fail to getstripe for $DIR/$tdir/f0"

	local saved_flags1=$($LFS getstripe $DIR/$tdir/f0 | head -n 10 |
			     awk '/lcme_flags/ { print $2 }')
	local saved_flags2=$($LFS getstripe $DIR/$tdir/f0 | tail -n 10 |
			     awk '/lcme_flags/ { print $2 }')

	echo "Inject failure, to simulate the case of missing the MDT-object"
	#define OBD_FAIL_LFSCK_LOST_MDTOBJ	0x1616
	do_facet mds1 $LCTL set_param fail_loc=0x1616
	rm -f $DIR/$tdir/f0 || error "(3) Fail to remove $DIR/$tdir/f0"

	sync
	sleep 2
	do_facet mds1 $LCTL set_param fail_loc=0

	echo "Trigger layout LFSCK on all devices to find out orphan OST-object"
	$START_LAYOUT -r -o || error "(4) Fail to start LFSCK for layout!"

	for k in $(seq $MDSCOUNT); do
		# The LFSCK status query internal is 30 seconds. For the case
		# of some LFSCK_NOTIFY RPCs failure/lost, we will wait enough
		# time to guarantee the status sync up.
		wait_update_facet mds${k} "$LCTL get_param -n \
			mdd.$(facet_svc mds${k}).lfsck_layout |
			awk '/^status/ { print \\\$2 }'" "completed" 32 ||
			error "(5) MDS${k} is not the expected 'completed'"
	done

	for k in $(seq $OSTCOUNT); do
		local cur_status=$(do_facet ost${k} $LCTL get_param -n \
				obdfilter.$(facet_svc ost${k}).lfsck_layout |
				awk '/^status/ { print $2 }')
		[ "$cur_status" == "completed" ] ||
		error "(6) OST${k} Expect 'completed', but got '$cur_status'"
	done

	local count=$(do_facet mds1 $LCTL get_param -n \
		      mdd.$(facet_svc mds1).lfsck_layout |
		      awk '/^repaired_orphan/ { print $2 }')
	[ $count -eq 6 ] || error "(7) Expect 9 fixed on mds1, but got: $count"

	local name=$MOUNT/.lustre/lost+found/MDT0000/${fid}-R-0
	count=$($LFS getstripe --mirror-count $name)
	[ $count -eq 2 ] || error "(8) $DIR/$tdir/f0 has $count mirrors"

	count=$($LFS getstripe --component-count $name)
	[ $count -eq 4 ] || error "(9) $DIR/$tdir/f0 has $count components"

	local flags=$($LFS getstripe $name | head -n 10 |
		awk '/lcme_flags/ { print $2 }')
	[ "$flags" == "$saved_flags1" ] || {
		$LFS getstripe $name
		error "(10) expect flags $saved_flags1, got $flags"
	}

	flags=$($LFS getstripe $name | tail -n 10 |
		awk '/lcme_flags/ { print $2 }')
	[ "$flags" == "$saved_flags2" ] || {
		$LFS getstripe $name
		error "(11) expect flags $saved_flags2, got $flags"
	}
}
run_test 36c "rebuild LOV EA for mirrored file (3)"

test_37()
{
	local PID
	local rc
	local t_dir="$DIR/$tdir/d0"
	check_mount_and_prep

	$LFS mkdir -i 0 $t_dir || error "(2) Fail to mkdir $t_dir on MDT0"
	multiop_bg_pause $t_dir D_c || { error "multiop failed: $?"; return 1; }
	PID=$!
	rmdir $t_dir

	$START_NAMESPACE -r -A || {
	    error "(3) Fail to start LFSCK for namespace!"; kill -USR1 $PID; }

	wait_all_targets_blocked namespace completed 4
	stat $t_dir && rc=1
	kill -USR1 $PID
	return $rc
}
run_test 37 "LFSCK must skip a ORPHAN"

test_38()
{
	[[ "$MDS1_VERSION" -le $(version_code 2.12.51) ]] &&
		skip "Need MDS version newer than 2.12.51"

	test_mkdir $DIR/$tdir
	local uuid1=$(cat /proc/sys/kernel/random/uuid)
	local uuid2=$(cat /proc/sys/kernel/random/uuid)

	# create foreign file
	$LFS setstripe --foreign=none --flags 0xda05 \
		-x "${uuid1}@${uuid2}" $DIR/$tdir/$tfile ||
		error "$DIR/$tdir/$tfile: create failed"

	$LFS getstripe -v $DIR/$tdir/$tfile |
		grep "lfm_magic:.*0x0BD70BD0" ||
		error "$DIR/$tdir/$tfile: invalid LOV EA foreign magic"
	# lfm_length is LOV EA size - sizeof(lfm_magic) - sizeof(lfm_length)
	$LFS getstripe -v $DIR/$tdir/$tfile | grep "lfm_length:.*73" ||
		error "$DIR/$tdir/$tfile: invalid LOV EA foreign size"
	$LFS getstripe -v $DIR/$tdir/$tfile | grep "lfm_type:.*none" ||
		error "$DIR/$tdir/$tfile: invalid LOV EA foreign type"
	$LFS getstripe -v $DIR/$tdir/$tfile |
		grep "lfm_flags:.*0x0000DA05" ||
		error "$DIR/$tdir/$tfile: invalid LOV EA foreign flags"
	$LFS getstripe $DIR/$tdir/$tfile |
		grep "lfm_value:.*${uuid1}@${uuid2}" ||
		error "$DIR/$tdir/$tfile: invalid LOV EA foreign value"

	# modify striping should fail
	$LFS setstripe -c 2 $DIR/$tdir/$tfile &&
		error "$DIR/$tdir/$tfile: setstripe should fail"

	$START_NAMESPACE -r -A || error "Fail to start LFSCK for namespace"

	wait_all_targets_blocked namespace completed 1

	# check that "global" namespace_repaired == 0 !!!
	local repaired=$(do_facet mds1 \
			 "$LCTL lfsck_query -t all -M ${FSNAME}-MDT0000 |
			 awk '/^namespace_repaired/ { print \\\$2 }'")
	[ $repaired -eq 0 ] ||
		error "(2) Expect no namespace repair, but got: $repaired"

	$START_LAYOUT -A -r || error "Fail to start LFSCK for layout"

	wait_all_targets_blocked layout completed 2

	# check that "global" layout_repaired == 0 !!!
	local repaired=$(do_facet mds1 \
			 "$LCTL lfsck_query -t all -M ${FSNAME}-MDT0000 |
			 awk '/^layout_repaired/ { print \\\$2 }'")
	[ $repaired -eq 0 ] ||
		error "(2) Expect no layout repair, but got: $repaired"

	echo "post-lfsck checks of foreign file"

	$LFS getstripe -v $DIR/$tdir/$tfile |
		grep "lfm_magic:.*0x0BD70BD0" ||
		error "$DIR/$tdir/$tfile: invalid LOV EA foreign magic"
	# lfm_length is LOV EA size - sizeof(lfm_magic) - sizeof(lfm_length)
	$LFS getstripe -v $DIR/$tdir/$tfile | grep "lfm_length:.*73" ||
		error "$DIR/$tdir/$tfile: invalid LOV EA foreign size"
	$LFS getstripe -v $DIR/$tdir/$tfile | grep "lfm_type:.*none" ||
		error "$DIR/$tdir/$tfile: invalid LOV EA foreign type"
	$LFS getstripe -v $DIR/$tdir/$tfile |
		grep "lfm_flags:.*0x0000DA05" ||
		error "$DIR/$tdir/$tfile: invalid LOV EA foreign flags"
	$LFS getstripe $DIR/$tdir/$tfile |
		grep "lfm_value:.*${uuid1}@${uuid2}" ||
		error "$DIR/$tdir/$tfile: invalid LOV EA foreign value"

	# modify striping should fail
	$LFS setstripe -c 2 $DIR/$tdir/$tfile &&
		error "$DIR/$tdir/$tfile: setstripe should fail"

	# R/W should fail
	cat $DIR/$tdir/$tfile && "$DIR/$tdir/$tfile: read should fail"
	cat /etc/passwd > $DIR/$tdir/$tfile &&
		error "$DIR/$tdir/$tfile: write should fail"

	#remove foreign file
	rm $DIR/$tdir/$tfile ||
		error "$DIR/$tdir/$tfile: remove of foreign file has failed"
}
run_test 38 "LFSCK does not break foreign file and reverse is also true"

test_39()
{
	[[ "$MDS1_VERSION" -le $(version_code 2.12.51) ]] &&
		skip "Need MDS version newer than 2.12.51"

	test_mkdir $DIR/$tdir
	local uuid1=$(cat /proc/sys/kernel/random/uuid)
	local uuid2=$(cat /proc/sys/kernel/random/uuid)

	# create foreign dir
	$LFS mkdir --foreign=none --xattr="${uuid1}@${uuid2}" --flags=0xda05 \
		$DIR/$tdir/${tdir}2 ||
		error "$DIR/$tdir/${tdir}2: create failed"

	$LFS getdirstripe -v $DIR/$tdir/${tdir}2 |
		grep "lfm_magic:.*0x0CD50CD0" ||
		error "$DIR/$tdir/${tdir}2: invalid LMV EA magic"
	# lfm_length is LMV EA size - sizeof(lfm_magic) - sizeof(lfm_length)
	# - sizeof(lfm_type) - sizeof(lfm_flags)
	$LFS getdirstripe -v $DIR/$tdir/${tdir}2 | grep "lfm_length:.*73" ||
		error "$DIR/$tdir/${tdir}2: invalid LMV EA size"
	$LFS getdirstripe -v $DIR/$tdir/${tdir}2 | grep "lfm_type:.*none" ||
		error "$DIR/$tdir/${tdir}2: invalid LMV EA type"
	$LFS getdirstripe -v $DIR/$tdir/${tdir}2 |
		grep "lfm_flags:.*0x0000DA05" ||
		error "$DIR/$tdir/${tdir}2: invalid LMV EA flags"
	$LFS getdirstripe $DIR/$tdir/${tdir}2 |
		grep "lfm_value.*${uuid1}@${uuid2}" ||
		error "$DIR/$tdir/${tdir}2: invalid LMV EA value"

	# file create in dir should fail
	touch $DIR/$tdir/${tdir}2/$tfile &&
		"$DIR/${tdir}2: file create should fail"

	# chmod should work
	chmod 777 $DIR/$tdir/${tdir}2 ||
		error "$DIR/${tdir}2: chmod failed"

	# chown should work
	chown $RUNAS_ID:$RUNAS_GID $DIR/$tdir/${tdir}2 ||
		error "$DIR/${tdir}2: chown failed"

	$START_NAMESPACE -r -A || error "Fail to start LFSCK for namespace"

	wait_all_targets_blocked namespace completed 1

	# check that "global" namespace_repaired == 0 !!!
	local repaired=$(do_facet mds1 \
			 "$LCTL lfsck_query -t all -M ${FSNAME}-MDT0000 |
			 awk '/^namespace_repaired/ { print \\\$2 }'")
	[ $repaired -eq 0 ] ||
		error "(2) Expect nothing to be repaired, but got: $repaired"

	$START_LAYOUT -A -r || error "Fail to start LFSCK for layout"

	wait_all_targets_blocked layout completed 2

	# check that "global" layout_repaired == 0 !!!
	local repaired=$(do_facet mds1 \
			 "$LCTL lfsck_query -t all -M ${FSNAME}-MDT0000 |
			 awk '/^layout_repaired/ { print \\\$2 }'")
	[ $repaired -eq 0 ] ||
		error "(2) Expect no layout repair, but got: $repaired"

	echo "post-lfsck checks of foreign dir"

	$LFS getdirstripe -v $DIR/$tdir/${tdir}2 |
		grep "lfm_magic:.*0x0CD50CD0" ||
		error "$DIR/$tdir/${tdir}2: invalid LMV EA magic"
	# lfm_length is LMV EA size - sizeof(lfm_magic) - sizeof(lfm_length)
	# - sizeof(lfm_type) - sizeof(lfm_flags)
	$LFS getdirstripe -v $DIR/$tdir/${tdir}2 | grep "lfm_length:.*73" ||
		error "$DIR/$tdir/${tdir}2: invalid LMV EA size"
	$LFS getdirstripe -v $DIR/$tdir/${tdir}2 | grep "lfm_type:.*none" ||
		error "$DIR/$tdir/${tdir}2: invalid LMV EA type"
	$LFS getdirstripe -v $DIR/$tdir/${tdir}2 |
		grep "lfm_flags:.*0x0000DA05" ||
		error "$DIR/$tdir/${tdir}2: invalid LMV EA flags"
	$LFS getdirstripe $DIR/$tdir/${tdir}2 |
		grep "lfm_value.*${uuid1}@${uuid2}" ||
		error "$DIR/$tdir/${tdir}2: invalid LMV EA value"

	# file create in dir should fail
	touch $DIR/$tdir/${tdir}2/$tfile &&
		"$DIR/${tdir}2: file create should fail"

	# chmod should work
	chmod 777 $DIR/$tdir/${tdir}2 ||
		error "$DIR/${tdir}2: chmod failed"

	# chown should work
	chown $RUNAS_ID:$RUNAS_GID $DIR/$tdir/${tdir}2 ||
		error "$DIR/${tdir}2: chown failed"

	#remove foreign dir
	rmdir $DIR/$tdir/${tdir}2 ||
		error "$DIR/$tdir/${tdir}2: remove of foreign dir has failed"
}
run_test 39 "LFSCK does not break foreign dir and reverse is also true"

test_40a() {
	[[ $MDSCOUNT -ge 2 ]] || skip "needs >= 2 MDTs"

	check_mount_and_prep
	$LFS mkdir -i 1 $DIR/$tdir/dir1
	$LFS setstripe -E 1M -c1 -S 1M -E 128M -c2 -S 4M -E eof $DIR/$tdir/dir1

	touch $DIR/$tdir/dir1/f1
	local layout1=$(get_layout_param $DIR/$tdir/dir1/f1)

	echo "Migrate $DIR/$tdir/dir1 from MDT1 to MDT0"
	$LFS migrate -m 0 $DIR/$tdir/dir1

	echo "trigger LFSCK for layout"
	do_facet $SINGLEMDS $LCTL lfsck_start -M ${MDT_DEV} -t layout -r

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT
		error "(2) unexpected status"
	}

	local layout2=$(get_layout_param $DIR/$tdir/dir1/f1)

	[[ "$layout1" == "$layout2" ]] || error "layout lost after lfsck"
}
run_test 40a "LFSCK correctly fixes lmm_oi in composite layout"

test_41()
{
	local old_debug=$(do_facet $SINGLEMDS $LCTL get_param -n debug)

	do_facet $SINGLEMDS $LCTL set_param debug=+lfsck
	$LFS setstripe -E 1G -z 64M -E -1 -z 128M $DIR/$tfile
	do_facet $SINGLEMDS $LCTL dk > /dev/null

	echo "trigger LFSCK for SEL layout"
	do_facet $SINGLEMDS $LCTL lfsck_start -M ${MDT_DEV} -A -t all -r -n on
	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" 32 || {
		$SHOW_LAYOUT
		error "(2) unexpected status"
	}

	local errors=$(do_facet $SINGLEMDS $LCTL dk |
		       grep "lfsck_layout_verify_header")

	[[ "x$errors" == "x" ]] || {
		echo "$errors"
		error "lfsck failed"
	}

	do_facet $SINGLEMDS "$LCTL set_param debug='$old_debug'"
}
run_test 41 "SEL support in LFSCK"

# restore MDS/OST size
MDSSIZE=${SAVED_MDSSIZE}
OSTSIZE=${SAVED_OSTSIZE}
OSTCOUNT=${SAVED_OSTCOUNT}

# cleanup the system at last
REFORMAT="yes" cleanup_and_setup_lustre

complete $SECONDS
check_and_cleanup_lustre
exit_status
