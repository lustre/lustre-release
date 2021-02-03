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

ALWAYS_EXCEPT="$SANITY_SCRUB_EXCEPT"

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

build_test_filter

require_dsh_mds || exit 0

load_modules

if ! check_versions; then
	skip "It is NOT necessary to test scrub under interoperation mode"
	exit 0
fi

cleanupall

SAVED_MDSSIZE=${MDSSIZE}
SAVED_OSTSIZE=${OSTSIZE}
SAVED_OSTCOUNT=${OSTCOUNT}

# use small MDS + OST size to speed formatting time
# do not use too small MDSSIZE/OSTSIZE, which affect the default journal size
# 400M MDT device can guarantee uninitialized groups during the OI scrub
[[ $MDSSIZE < 400000 || "$mds1_FSTYPE" == ldiskfs ]] && MDSSIZE=400000
[[ $OSTSIZE < 400000 || "$ost1_FSTYPE" == ldiskfs ]] && OSTSIZE=400000

# no need too many OSTs, to reduce the format/start/stop overhead
[ $OSTCOUNT -gt 4 ] && OSTCOUNT=4

# build up a clean test environment.
REFORMAT="yes" check_and_setup_lustre

MDT_DEV="${FSNAME}-MDT0000"
OST_DEV="${FSNAME}-OST0000"

scrub_start() {
	local error_id=$1
	local n

	# use "lfsck_start -A" when we no longer need testing interop
	for n in $(seq $MDSCOUNT); do
		do_facet mds$n $LCTL lfsck_start -M $(facet_svc mds$n) \
			-t scrub "$@" ||
			error "($error_id) Failed to start OI scrub on mds$n"
	done
}

scrub_stop() {
	local error_id=$1
	local n

	# use "lfsck_stop -A" when we no longer need testing interop
	for n in $(seq $MDSCOUNT); do
		do_facet mds$n $LCTL lfsck_stop -M $(facet_svc mds$n) ||
			error "($error_id) Failed to stop OI scrub on mds$n"
	done
}

scrub_status() {
	local n=$1

	do_facet mds$n $LCTL get_param -n osd-*.$(facet_svc mds$n).oi_scrub
}

START_SCRUB="do_facet $SINGLEMDS $LCTL lfsck_start -M ${MDT_DEV} -t scrub"
START_SCRUB_ON_OST="do_facet ost1 $LCTL lfsck_start -M ${OST_DEV} -t scrub"
STOP_SCRUB="do_facet $SINGLEMDS $LCTL lfsck_stop -M ${MDT_DEV}"
SHOW_SCRUB="do_facet $SINGLEMDS \
		$LCTL get_param -n osd-*.${MDT_DEV}.oi_scrub"
SHOW_SCRUB_ON_OST="do_facet ost1 \
		$LCTL get_param -n osd-*.${OST_DEV}.oi_scrub"
MOUNT_OPTS_SCRUB="-o user_xattr"
MOUNT_OPTS_NOSCRUB="-o user_xattr,noscrub"

scrub_prep() {
	local nfiles=$1
	local inject=$2
	local n

	check_mount_and_prep

	echo "preparing... $(date)"
	for n in $(seq $MDSCOUNT); do
		echo "creating $nfiles files on mds$n"
		test_mkdir -i $((n - 1)) -c1 $DIR/$tdir/mds$n ||
			error "Failed to create directory mds$n"
		cp $LUSTRE/tests/*.sh $DIR/$tdir/mds$n ||
			error "Failed to copy files to mds$n"
		mkdir -p $DIR/$tdir/mds$n/d_$tfile ||
			error "mkdir failed on mds$n"
		touch $DIR/$tdir/mds$n/d_$tfile/f1 > \
			/dev/null || error "create failed on mds$n"
		dd if=/dev/zero of=$DIR/$tdir/mds$n/d_$tfile/f2 bs=1M count=1 ||
		       	error "write failed on mds$n"
		if [[ $nfiles -gt 0 ]]; then
			createmany -m $DIR/$tdir/mds$n/$tfile $nfiles > \
				/dev/null || error "createmany failed on mds$n"
		fi
	done
	echo "prepared $(date)."

	[ ! -z $inject ] && [ $inject -eq 2 ] && {
		#define OBD_FAIL_OSD_NO_OI_ENTRY	0x198
		do_nodes $(comma_list $(mdts_nodes)) \
				$LCTL set_param fail_loc=0x198

		for n in $(seq $MDSCOUNT); do
			cp $LUSTRE/tests/runas $DIR/$tdir/mds$n ||
				error "Fail to copy runas to MDS$n"
		done

		do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param fail_loc=0
	}

	[ ! -z $inject ] && [ $inject -eq 1 ] &&
		[ "$mds1_FSTYPE" = "zfs" ] && {
		#define OBD_FAIL_OSD_FID_MAPPING	0x193
		do_nodes $(comma_list $(mdts_nodes)) \
			$LCTL set_param fail_loc=0x193

		for n in $(seq $MDSCOUNT); do
			chmod 0400 $DIR/$tdir/mds$n/test-framework.sh
			chmod 0400 $DIR/$tdir/mds$n/sanity-scrub.sh
		done

		do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param fail_loc=0
	}

	cleanup_mount $MOUNT > /dev/null || error "Fail to stop client!"

	# sync local transactions on every MDT
	do_nodes $(comma_list $(mdts_nodes)) \
		"$LCTL set_param -n osd*.*MDT*.force_sync=1"

	# wait for a while to cancel update logs after transactions committed.
	sleep 3

	# sync again to guarantee all things done.
	do_nodes $(comma_list $(mdts_nodes)) \
		"$LCTL set_param -n osd*.*MDT*.force_sync=1"

	for n in $(seq $MDSCOUNT); do
		echo "stop mds$n"
		stop mds$n > /dev/null || error "Fail to stop MDS$n!"
	done

	[ ! -z $inject ] && [ "$mds1_FSTYPE" = "ldiskfs" ] && {
		if [ $inject -eq 1 ]; then
			for n in $(seq $MDSCOUNT); do
				mds_backup_restore mds$n ||
					error "Backup/restore on mds$n failed"
			done
		elif [ $inject -eq 2 ]; then
			scrub_remove_ois 1
		fi
	}
}

scrub_start_mds() {
	local error_id=$1
	local opts=$2
	local n

	for n in $(seq $MDSCOUNT); do
		start mds$n $(mdsdevname $n) $opts >/dev/null ||
			error "($error_id) Failed to start mds$n"
	done
}

scrub_stop_mds() {
	local error_id=$1
	local n

	for n in $(seq $MDSCOUNT); do
		echo "stopping mds$n"
		stop mds$n >/dev/null ||
			error "($error_id) Failed to stop mds$n"
	done
}

scrub_check_status() {
	local error_id=$1
	local expected=$2
	local n

	for n in $(seq $MDSCOUNT); do
		wait_update_facet mds$n "$LCTL get_param -n \
			osd-*.$(facet_svc mds$n).oi_scrub |
			awk '/^status/ { print \\\$2 }'" "$expected" 6 ||
			error "($error_id) Expected '$expected' on mds$n"
	done
}

scrub_check_flags() {
	local error_id=$1
	local expected=$2
	local actual
	local n

	for n in $(seq $MDSCOUNT); do
		actual=$(do_facet mds$n $LCTL get_param -n \
			osd-*.$(facet_svc mds$n).oi_scrub |
			awk '/^flags/ { print $2 }')
		if [ "$actual" != "$expected" ]; then
			error "($error_id) Expected '$expected' on mds$n, but" \
			       "got '$actual'"
		fi
	done
}

scrub_check_params() {
	local error_id=$1
	local expected=$2
	local actual
	local n

	for n in $(seq $MDSCOUNT); do
		actual=$(do_facet mds$n $LCTL get_param -n \
			osd-*.$(facet_svc mds$n).oi_scrub |
			awk '/^param/ { print $2 }')
		if [ "$actual" != "$expected" ]; then
			error "($error_id) Expected '$expected' on mds$n, but" \
			       "got '$actual'"
		fi
	done
}

scrub_check_repaired() {
	local error_id=$1
	local expected=$2
	local dryrun=$3
	local actual
	local n

	for n in $(seq $MDSCOUNT); do
		if [ $dryrun -eq 1 ]; then
			actual=$(do_facet mds$n $LCTL get_param -n \
				osd-*.$(facet_svc mds$n).oi_scrub |
				awk '/^inconsistent:/ { print $2 }')
		else
			actual=$(do_facet mds$n $LCTL get_param -n \
				osd-*.$(facet_svc mds$n).oi_scrub |
				awk '/^updated:/ { print $2 }')
		fi

		if [ $expected -eq 0 -a $actual -ne 0 ]; then
			error "($error_id) Expected no repaired on mds$n, but" \
			       "got '$actual'"
		fi

		if [ $expected -ne 0 -a $actual -lt $expected ]; then
			error "($error_id) Expected '$expected' on mds$n, but" \
			       "got '$actual'"
		fi
	done
}

scrub_check_data() {
	local error_id=$1
	local n

	for n in $(seq $MDSCOUNT); do
		diff -q $LUSTRE/tests/test-framework.sh \
			$DIR/$tdir/mds$n/test-framework.sh ||
			error "($error_id) File data check failed"
	done
}

scrub_check_data2() {
	local filename=$1
	local error_id=$2
	local n

	for n in $(seq $MDSCOUNT); do
		diff -q $LUSTRE/tests/$filename \
			$DIR/$tdir/mds$n/$filename ||
			error "($error_id) File data check failed"
	done
}

scrub_remove_ois() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] && return

	local error_id=$1
	local index=$2
	local n

	for n in $(seq $MDSCOUNT); do
		mds_remove_ois mds$n $index ||
			error "($error_id) Failed to remove OI .$index on mds$n"
	done
}

scrub_enable_auto() {
	do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param -n \
		osd-*.*.auto_scrub=1
}

full_scrub_ratio() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] && return

	local ratio=$1

	do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param -n \
		osd-*.*.full_scrub_ratio=$ratio
}

full_scrub_threshold_rate() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] && return

	local rate=$1

	do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param -n \
		osd-*.*.full_scrub_threshold_rate=$rate
}

scrub_enable_index_backup() {
	do_nodes $(comma_list $(all_server_nodes)) $LCTL set_param -n \
		osd-*.*.index_backup=1
}

scrub_disable_index_backup() {
	do_nodes $(comma_list $(all_server_nodes)) $LCTL set_param -n \
		osd-*.*.index_backup=0
}

test_0() {
	scrub_prep 0
	echo "starting MDTs without disabling OI scrub"
	scrub_start_mds 1 "$MOUNT_OPTS_SCRUB"
	scrub_check_status 2 init
	scrub_check_flags 3 ""
	mount_client $MOUNT || error "(4) Fail to start client!"
	scrub_check_data 5
}
run_test 0 "Do not auto trigger OI scrub for non-backup/restore case"

test_1a() {
	[ -n "$FILESET" ] && skip "Not functional for FILESET set"

	scrub_prep 0
	echo "start $SINGLEMDS without disabling OI scrub"
	scrub_start_mds 1 "$MOUNT_OPTS_SCRUB"

	local FLAGS=$($SHOW_SCRUB | awk '/^flags/ { print $2 }')
	[ -z "$FLAGS" ] || error "(3) Expect empty flags, but got '$FLAGS'"

	mount_client $MOUNT || error "(4) Fail to start client!"
	#define OBD_FAIL_OSD_FID_MAPPING			0x193
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x193
	# update .lustre OI mapping
	touch $MOUNT/.lustre
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	umount_client $MOUNT || error "(5) Fail to stop client!"

	echo "stop $SINGLEMDS"
	stop $SINGLEMDS > /dev/null || error "(6) Fail to stop MDS!"

	echo "start $SINGLEMDS with disabling OI scrub"
	start $SINGLEMDS $(mdsdevname 1) $MOUNT_OPTS_NOSCRUB > /dev/null ||
		error "(7) Fail to start MDS!"

	local FLAGS=$($SHOW_SCRUB | awk '/^flags/ { print $2 }')
	[ "$FLAGS" == "inconsistent" ] ||
		error "(9) Expect 'inconsistent', but got '$FLAGS'"
}
run_test 1a "Auto trigger initial OI scrub when server mounts"

test_1b() {
	scrub_prep 0 2
	echo "start MDTs without disabling OI scrub"
	scrub_start_mds 2 "$MOUNT_OPTS_SCRUB"
	[ "$mds1_FSTYPE" != "ldiskfs" ] ||
		scrub_check_status 3 completed
	mount_client $MOUNT || error "(4) Fail to start client!"
	scrub_check_data2 runas 5
	scrub_check_status 6 completed
}
run_test 1b "Trigger OI scrub when MDT mounts for OI files remove/recreate case"

test_1c() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] &&
		skip "ldiskfs special test"

	local index

	# OI files to be removed:
	# idx 0: oi.16.0
	# idx 2: oi.16.{2,4,8,16,32}
	# idx 3: oi.16.{3,9,27}
	for index in 0 2 3; do
		scrub_prep 0
		scrub_remove_ois 1 $index
		echo "start MDTs with OI scrub disabled"
		scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
		scrub_check_flags 3 recreated
		scrub_start 4
		scrub_check_status 5 completed
		scrub_check_flags 6 ""
	done
}
run_test 1c "Auto detect kinds of OI file(s) removed/recreated cases"

test_2() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] &&
		skip "ldiskfs special test"

	scrub_prep 0 1
	echo "starting MDTs without disabling OI scrub"
	scrub_start_mds 2 "$MOUNT_OPTS_SCRUB"
	scrub_check_status 3 completed
	mount_client $MOUNT || error "(4) Fail to start client!"
	scrub_check_data 5
}
run_test 2 "Trigger OI scrub when MDT mounts for backup/restore case"

# test_3 is obsolete, it will be covered by test_5.
test_3() {
	formatall > /dev/null
	setupall > /dev/null

	scrub_prep 0 1
	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	scrub_check_status 3 init
	[ "$mds1_FSTYPE" != "ldiskfs" ] ||
		scrub_check_flags 4 recreated,inconsistent
}
#run_test 3 "Do not trigger OI scrub when MDT mounts if 'noscrub' specified"

test_4a() {
	scrub_prep 0 1
	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	[ "$mds1_FSTYPE" != "ldiskfs" ] ||
		scrub_check_flags 4 recreated,inconsistent
	mount_client $MOUNT || error "(5) Fail to start client!"
	scrub_enable_auto
	full_scrub_ratio 0
	scrub_check_data 6
	sleep 3

	scrub_check_status 7 completed
	scrub_check_flags 8 ""

	local -a updated0
	for n in $(seq $MDSCOUNT); do
		updated0[$n]=$(scrub_status $n |
			       awk '/^prior_updated/ { print $2 }')
	done

	scrub_check_data2 sanity-scrub.sh 9
	sleep 3

	local -a updated1
	for n in $(seq $MDSCOUNT); do
		updated1[$n]=$(scrub_status $n |
			       awk '/^prior_updated/ { print $2 }')
		[ ${updated0[$n]} -eq ${updated1[$n]} ] ||
			error "(10) NOT auto trigger full scrub as expected"
	done
}
run_test 4a "Auto trigger OI scrub if bad OI mapping was found (1)"

test_4b() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] &&
		skip "ldiskfs special test"

	scrub_prep 5 1
	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	scrub_check_flags 4 recreated,inconsistent
	mount_client $MOUNT || error "(5) Fail to start client!"
	scrub_enable_auto
	full_scrub_ratio 10
	full_scrub_threshold_rate 10000
	scrub_check_data 6
	sleep 3

	scrub_check_status 7 completed
	scrub_check_flags 8 ""

	local -a updated0
	for n in $(seq $MDSCOUNT); do
		updated0[$n]=$(scrub_status $n |
			       awk '/^prior_updated/ { print $2 }')

		echo "OI scrub on MDS$n status for the 1st time:"
		do_facet mds$n $LCTL get_param -n \
			osd-*.$(facet_svc mds$n).oi_scrub
	done

	scrub_check_data2 sanity-scrub.sh 9
	sleep 3

	scrub_check_status 10 completed
	scrub_check_flags 11 ""

	local -a updated1
	for n in $(seq $MDSCOUNT); do
		updated1[$n]=$(scrub_status $n |
			       awk '/^prior_updated/ { print $2 }')

		echo "OI scrub on MDS$n status for the 2nd time:"
		do_facet mds$n $LCTL get_param -n \
			osd-*.$(facet_svc mds$n).oi_scrub

		[ ${updated0[$n]} -lt ${updated1[$n]} ] ||
			error "(12) Auto trigger full scrub unexpectedly"
	done

	for n in $(seq $MDSCOUNT); do
		ls -l $DIR/$tdir/mds$n/*.sh > /dev/null ||
			error "(13) fail to ls"
	done
	sleep 3

	scrub_check_status 14 completed
	scrub_check_flags 15 ""

	for n in $(seq $MDSCOUNT); do
		updated0[$n]=$(scrub_status $n |
			       awk '/^prior_updated/ { print $2 }')

		echo "OI scrub on MDS$n status for the 3rd time:"
		do_facet mds$n $LCTL get_param -n \
			osd-*.$(facet_svc mds$n).oi_scrub

		[ ${updated0[$n]} -gt ${updated1[$n]} ] ||
			error "(16) Auto trigger full scrub unexpectedly"
	done

	for n in $(seq $MDSCOUNT); do
		ls -l $DIR/$tdir/mds$n/d_${tfile}/ || error "(17) fail to ls"
	done
	sleep 3

	for n in $(seq $MDSCOUNT); do
		updated1[$n]=$(scrub_status $n |
			       awk '/^prior_updated/ { print $2 }')
		[ ${updated0[$n]} -eq ${updated1[$n]} ] || {
			echo "OI scrub on MDS$n status for the 4th time:"
			do_facet mds$n $LCTL get_param -n \
				osd-*.$(facet_svc mds$n).oi_scrub

			error "(18) NOT auto trigger full scrub as expected"
		}
	done
}
run_test 4b "Auto trigger OI scrub if bad OI mapping was found (2)"

test_4c() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] &&
		skip "ldiskfs special test"

	scrub_prep 500 1
	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	scrub_check_flags 4 recreated,inconsistent
	mount_client $MOUNT || error "(5) Fail to start client!"
	scrub_enable_auto
	full_scrub_ratio 2
	full_scrub_threshold_rate 20
	scrub_check_data 6
	sleep 3

	scrub_check_status 7 completed
	scrub_check_flags 8 ""

	local -a updated0
	for n in $(seq $MDSCOUNT); do
		updated0[$n]=$(scrub_status $n |
			       awk '/^prior_updated/ { print $2 }')

		echo "OI scrub on MDS$n status for the 1st time:"
		do_facet mds$n $LCTL get_param -n \
			osd-*.$(facet_svc mds$n).oi_scrub
	done

	scrub_check_data2 sanity-scrub.sh 9
	sleep 3

	scrub_check_status 10 completed
	scrub_check_flags 11 ""

	local -a updated1
	for n in $(seq $MDSCOUNT); do
		updated1[$n]=$(scrub_status $n |
			       awk '/^prior_updated/ { print $2 }')

		echo "OI scrub on MDS$n status for the 2nd time:"
		do_facet mds$n $LCTL get_param -n \
			osd-*.$(facet_svc mds$n).oi_scrub

		[ ${updated0[$n]} -lt ${updated1[$n]} ] ||
			error "(12) Auto trigger full scrub unexpectedly"
	done

	for n in $(seq $MDSCOUNT); do
		ls -l $DIR/$tdir/mds$n/*.sh > /dev/null ||
			error "(13) fail to ls"
	done
	sleep 3

	scrub_check_status 14 completed
	scrub_check_flags 15 ""

	for n in $(seq $MDSCOUNT); do
		updated0[$n]=$(scrub_status $n |
			       awk '/^prior_updated/ { print $2 }')

		echo "OI scrub on MDS$n status for the 3rd time:"
		do_facet mds$n $LCTL get_param -n \
			osd-*.$(facet_svc mds$n).oi_scrub

		[ ${updated0[$n]} -gt ${updated1[$n]} ] ||
			error "(16) Auto trigger full scrub unexpectedly"
	done

	for n in $(seq $MDSCOUNT); do
		ls -l $DIR/$tdir/mds$n/${tfile}1 || error "(17) fail to ls"
	done
	sleep 3

	for n in $(seq $MDSCOUNT); do
		updated1[$n]=$(scrub_status $n |
			       awk '/^prior_updated/ { print $2 }')
		[ ${updated0[$n]} -eq ${updated1[$n]} ] || {
			echo "OI scrub on MDS$n status for the 4th time:"
			do_facet mds$n $LCTL get_param -n \
				osd-*.$(facet_svc mds$n).oi_scrub

			error "(18) NOT auto trigger full scrub as expected"
		}
	done
}
run_test 4c "Auto trigger OI scrub if bad OI mapping was found (3)"

test_4d() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] && skip "ldiskfs only test"

	check_mount_and_prep

	#define OBD_FAIL_OSD_DUPLICATE_MAP	0x19b
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0x19b
	for i in {1..100}; do
		echo $i > $DIR/$tdir/f_$i || error "write f_$i failed"
	done
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0

	for i in {101..200}; do
		echo $i > $DIR/$tdir/f_$i || error "write f_$i failed"
	done

	for i in {1..200}; do
		echo $i | cmp $DIR/$tdir/f_$i - || error "f_$i data corrupt"
	done
}
run_test 4d "FID in LMA mismatch with object FID won't block create"

test_5() {
	formatall > /dev/null
	setupall > /dev/null

	scrub_prep 100 1
	echo "starting MDTs with OI scrub disabled (1)"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	scrub_check_status 3 init
	[ "$mds1_FSTYPE" != "ldiskfs" ] ||
		scrub_check_flags 4 recreated,inconsistent
	mount_client $MOUNT || error "(5) Fail to start client!"
	scrub_enable_auto
	full_scrub_ratio 0

	#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_val=3 fail_loc=0x190

	scrub_check_data 6
	umount_client $MOUNT || error "(7) Fail to stop client!"
	scrub_check_status 8 scanning

	#define OBD_FAIL_OSD_SCRUB_CRASH	 0x191
	do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param fail_loc=0x191

	sleep 4
	scrub_stop_mds 9

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_loc=0 fail_val=0

	echo "starting MDTs with OI scrub disabled (2)"
	scrub_start_mds 10 "$MOUNT_OPTS_NOSCRUB"
	scrub_check_status 11 crashed
	scrub_stop_mds 12

	#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_val=3 fail_loc=0x190

	echo "starting MDTs without disabling OI scrub"
	scrub_start_mds 13 "$MOUNT_OPTS_SCRUB"
	scrub_check_status 14 scanning

	#define OBD_FAIL_OSD_SCRUB_FATAL	 0x192
	do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param fail_loc=0x192

	scrub_check_status 15 failed
	mount_client $MOUNT || error "(16) Fail to start client!"

	full_scrub_ratio 0
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_loc=0 fail_val=0

	local n
	declare -a pids

	for n in $(seq $MDSCOUNT); do
		stat $DIR/$tdir/mds$n/sanity-scrub.sh &
		pids[$n]=$!
	done

	for n in $(seq $MDSCOUNT); do
		wait ${pids[$n]} ||
			error "(18) Fail to stat mds$n/sanity-scrub.sh"
	done

	scrub_check_status 19 completed
	scrub_check_flags 20 ""
}
run_test 5 "OI scrub state machine"

test_6() {
	scrub_prep 100 1
	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	[ "$mds1_FSTYPE" != "ldiskfs" ] ||
		scrub_check_flags 4 recreated,inconsistent
	mount_client $MOUNT || error "(5) Fail to start client!"
	scrub_enable_auto
	full_scrub_ratio 0

	#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_val=2 fail_loc=0x190

	scrub_check_data 6

	# Sleep 5 sec to guarantee at least one object processed by OI scrub
	sleep 5
	# Fail the OI scrub to guarantee there is at least one checkpoint
	#define OBD_FAIL_OSD_SCRUB_FATAL	 0x192
	do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param fail_loc=0x192

	scrub_check_status 7 failed

	#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_val=3 fail_loc=0x190

	local n
	for n in $(seq $MDSCOUNT); do
		# stat will re-trigger OI scrub
		stat $DIR/$tdir/mds$n/sanity-scrub.sh ||
			error "(8) Failed to stat mds$n/sanity-scrub.sh"
	done

	umount_client $MOUNT || error "(9) Fail to stop client!"
	scrub_check_status 10 scanning

	#define OBD_FAIL_OSD_SCRUB_CRASH	 0x191
	do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param fail_loc=0x191

	sleep 4
	local -a position0
	for n in $(seq $MDSCOUNT); do
		position0[$n]=$(scrub_status $n |
			awk '/^last_checkpoint_position/ {print $2}')
		position0[$n]=$((${position0[$n]} + 1))
	done

	scrub_stop_mds 11

	#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_val=3 fail_loc=0x190

	echo "starting MDTs without disabling OI scrub"
	scrub_start_mds 12 "$MOUNT_OPTS_SCRUB"

	scrub_check_status 13 scanning

	local -a position1
	for n in $(seq $MDSCOUNT); do
		position1[$n]=$(scrub_status $n |
			awk '/^latest_start_position/ {print $2}')
		if [ ${position0[$n]} -ne ${position1[$n]} ]; then
			error "(14) Expected position ${position0[$n]}, but" \
				"got ${position1[$n]}"
		fi
	done

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_loc=0 fail_val=0

	scrub_check_status 15 completed
	scrub_check_flags 16 ""
}
run_test 6 "OI scrub resumes from last checkpoint"

test_7() {
	scrub_prep 500 1
	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	[ "$mds1_FSTYPE" != "ldiskfs" ] ||
		scrub_check_flags 4 recreated,inconsistent
	mount_client $MOUNT || error "(5) Fail to start client!"
	scrub_enable_auto
	full_scrub_ratio 0

	#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_val=3 fail_loc=0x190

	scrub_check_data 6

	local n
	for n in $(seq $MDSCOUNT); do
		stat $DIR/$tdir/mds$n/${tfile}300 ||
			error "(7) Failed to stat mds$n/${tfile}300!"
	done

	scrub_check_status 8 scanning
	if [ "$mds1_FSTYPE" != "ldiskfs" ]; then
		scrub_check_flags 9 inconsistent,auto
	else
		scrub_check_flags 9 recreated,inconsistent,auto
	fi

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_loc=0 fail_val=0

	scrub_check_status 10 completed
	scrub_check_flags ""
}
run_test 7 "System is available during OI scrub scanning"

test_8() {
	scrub_prep 128 1
	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	[ "$mds1_FSTYPE" != "ldiskfs" ] ||
		scrub_check_flags 4 recreated,inconsistent

	#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_val=1 fail_loc=0x190

	scrub_start 5
	scrub_check_status 6 scanning
	scrub_stop 7
	scrub_check_status 8 stopped
	scrub_start 9
	scrub_check_status 10 scanning

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_loc=0 fail_val=0

	scrub_check_status 11 completed
	scrub_check_flags 12 ""
}
run_test 8 "Control OI scrub manually"

test_9() {
	# Skip scrub speed test for ZFS because of performance unstable
	[ "$mds1_FSTYPE" != "ldiskfs" ] &&
		skip "test scrub speed only on ldiskfs"

	if [ -z "$(grep "processor.*: 1" /proc/cpuinfo)" ]; then
		skip "Testing on UP system, the speed may be inaccurate."
	fi

	scrub_prep 6000 1

	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	scrub_check_flags 4 recreated,inconsistent

	local BASE_SPEED1=100
	local RUN_TIME1=10
	# OI scrub should run with full speed under inconsistent case
	scrub_start 5 -s $BASE_SPEED1

	sleep $RUN_TIME1
	scrub_check_status 6 completed
	scrub_check_flags 7 ""

	# OI scrub should run with limited speed under non-inconsistent case
	scrub_start 8 -s $BASE_SPEED1 -r

	sleep $RUN_TIME1
	scrub_check_status 9 scanning

	# Do NOT ignore that there are 1024 pre-fetched items. And there
	# may be time error, normally it should be less than 2 seconds.
	# We allow another 20% schedule error.
	local PRE_FETCHED=1024
	local TIME_DIFF=2
	# MAX_MARGIN = 1.2 = 12 / 10
	local MAX_SPEED=$(((PRE_FETCHED + BASE_SPEED1 * \
		(RUN_TIME1 + TIME_DIFF)) / RUN_TIME1 * 12 / 10))
	local n
	for n in $(seq $MDSCOUNT); do
		local SPEED=$(scrub_status $n | \
			awk '/^average_speed/ { print $2 }')
		[ $SPEED -lt $MAX_SPEED ] ||
			error "(10) Got speed $SPEED, expected less than" \
				"$MAX_SPEED"
	done

	# adjust speed limit
	local BASE_SPEED2=300
	local RUN_TIME2=10
	for n in $(seq $MDSCOUNT); do
		do_facet mds$n $LCTL set_param -n \
			mdd.$(facet_svc mds$n).lfsck_speed_limit $BASE_SPEED2
	done
	sleep $RUN_TIME2

	# 30% margin
	local MARGIN=3
	local MIN_SPEED=$(((PRE_FETCHED + \
			    BASE_SPEED1 * (RUN_TIME1 - TIME_DIFF) + \
			    BASE_SPEED2 * (RUN_TIME2 - TIME_DIFF)) / \
			   (RUN_TIME1 + RUN_TIME2) * (10 - MARGIN) / 10))
	# MAX_MARGIN = 1.2 = 12 / 10
	MAX_SPEED=$(((PRE_FETCHED + \
		      BASE_SPEED1 * (RUN_TIME1 + TIME_DIFF) + \
		      BASE_SPEED2 * (RUN_TIME2 + TIME_DIFF)) / \
		     (RUN_TIME1 + RUN_TIME2) * (10 + MARGIN) / 10))
	for n in $(seq $MDSCOUNT); do
		SPEED=$(scrub_status $n | awk '/^average_speed/ { print $2 }')
		[ $SPEED -gt $MIN_SPEED ] ||
			error "(11) Got speed $SPEED, expected more than" \
				"$MIN_SPEED"
		[ $SPEED -lt $MAX_SPEED ] ||
			error "(12) Got speed $SPEED, expected less than" \
				"$MAX_SPEED"

		do_facet mds$n $LCTL set_param -n \
				mdd.$(facet_svc mds$n).lfsck_speed_limit 0
	done

	scrub_check_status 13 completed
}
run_test 9 "OI scrub speed control"

test_10a() {
	scrub_prep 0 1
	echo "starting mds$n with OI scrub disabled (1)"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	[ "$mds1_FSTYPE" != "ldiskfs" ] ||
		scrub_check_flags 4 recreated,inconsistent
	mount_client $MOUNT || error "(5) Fail to start client!"
	scrub_enable_auto
	full_scrub_ratio 0

	#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_val=1 fail_loc=0x190

	scrub_check_data 6
	scrub_check_status 7 scanning
	umount_client $MOUNT || error "(8) Fail to stop client!"
	scrub_stop_mds 9
	echo "starting MDTs with OI scrub disabled (2)"
	scrub_start_mds 10 "$MOUNT_OPTS_NOSCRUB"
	scrub_check_status 11 paused
	scrub_stop_mds 12
	echo "starting MDTs without disabling OI scrub"
	scrub_start_mds 13 "$MOUNT_OPTS_SCRUB"
	scrub_check_status 14 scanning

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_loc=0 fail_val=0

	scrub_check_status 15 completed
	scrub_check_flags 16 ""
}
run_test 10a "non-stopped OI scrub should auto restarts after MDS remount (1)"

# test_10b is obsolete, it will be coverded by related sanity-lfsck tests.
test_10b() {
	scrub_prep 0 1
	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	[ "$mds1_FSTYPE" != "ldiskfs" ] ||
		scrub_check_flags 4 recreated,inconsistent

	#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_val=3 fail_loc=0x190

	scrub_start 5
	scrub_check_status 6 scanning
	scrub_stop_mds 7
	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 8 "$MOUNT_OPTS_NOSCRUB"
	scrub_check_status 9 paused
	scrub_stop_mds 10
	echo "starting MDTs without disabling OI scrub"
	scrub_start_mds 11 "$MOUNT_OPTS_SCRUB"
	scrub_check_status 12 scanning

	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param fail_loc=0 fail_val=0

	scrub_check_status 13 completed
	scrub_check_flags 14 ""
}
#run_test 10b "non-stopped OI scrub should auto restarts after MDS remount (2)"

test_11() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] &&
		skip "ldiskfs special test"

	local CREATED=100
	local n

	check_mount_and_prep

	for n in $(seq $MDSCOUNT); do
		test_mkdir -i $((n - 1)) -c1 $DIR/$tdir/mds$n ||
			error "(1) Fail to mkdir $DIR/$tdir/mds$n"

		createmany -o $DIR/$tdir/mds$n/f $CREATED ||
			error "(2) Fail to create under $tdir/mds$n"
	done

	# reset OI scrub start point by force
	scrub_start 3 -r
	scrub_check_status 4 completed

	declare -a checked0
	declare -a checked1

	# OI scrub should skip the new created objects for the first accessing
	# notice we're creating a new llog for every OST on every startup
	# new features can make this even less stable, so we only check that
	# the number of skipped files is more than the number or known created
	local MINIMUM=$((CREATED + 1)) # files + directory
	for n in $(seq $MDSCOUNT); do
		local SKIPPED=$(scrub_status $n | awk '/^noscrub/ { print $2 }')
		[ $SKIPPED -lt $MINIMUM ] &&
			error "(5) Expect at least $MINIMUM objects" \
				"skipped on mds$n, but got $SKIPPED"

		checked0[$n]=$(scrub_status $n | awk '/^checked/ { print $2 }')
	done

	# reset OI scrub start point by force
	scrub_start 6 -r
	scrub_check_status 7 completed

	# OI scrub should skip the new created object only once
	for n in $(seq $MDSCOUNT); do
		SKIPPED=$(scrub_status $n | awk '/^noscrub/ { print $2 }')
		checked1[$n]=$(scrub_status $n | awk '/^checked/ { print $2 }')

		[ ${checked0[$n]} -ne ${checked1[$n]} -o $SKIPPED -eq 0 ] ||
			error "(8) Expect 0 objects skipped on mds$n, but" \
				"got $SKIPPED"
	done
}
run_test 11 "OI scrub skips the new created objects only once"

test_12() {
	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	#define OBD_FAIL_OSD_COMPAT_INVALID_ENTRY		0x195
	do_facet ost1 $LCTL set_param fail_loc=0x195
	local count=$(precreated_ost_obj_count 0 0)

	createmany -o $DIR/$tdir/f $((count + 32))
	umount_client $MOUNT || error "(1) Fail to stop client!"

	stop ost1 || error "(2) Fail to stop ost1"

	#define OBD_FAIL_OST_NODESTROY		 0x233
	do_facet ost1 $LCTL set_param fail_loc=0x233

	start ost1 $(ostdevname 1) $MOUNT_OPTS_NOSCRUB ||
		error "(3) Fail to start ost1"

	mount_client $MOUNT || error "(4) Fail to start client!"

	ls -ail $DIR/$tdir > /dev/null 2>&1 && error "(5) ls should fail"

	$START_SCRUB_ON_OST -r || error "(6) Fail to start OI scrub on OST!"

	do_facet ost1 $LCTL set_param fail_loc=0
	wait_update_facet ost1 "$LCTL get_param -n \
		osd-*.$(facet_svc ost1).oi_scrub |
		awk '/^status/ { print \\\$2 }'" "completed" 6 ||
		error "(7) Expected '$expected' on ost1"

	ls -ail $DIR/$tdir > /dev/null || {
		$SHOW_SCRUB_ON_OST
		error "(8) ls should succeed"
	}
}
run_test 12 "OI scrub can rebuild invalid /O entries"

test_13() {
	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	#define OBD_FAIL_OSD_COMPAT_NO_ENTRY		0x196
	do_facet ost1 $LCTL set_param fail_loc=0x196
	local count=$(precreated_ost_obj_count 0 0)

	createmany -o $DIR/$tdir/f $((count + 32))
	do_facet ost1 $LCTL set_param fail_loc=0

	umount_client $MOUNT || error "(1) Fail to stop client!"

	stop ost1 || error "(2) Fail to stop ost1"

	start ost1 $(ostdevname 1) $MOUNT_OPTS_NOSCRUB ||
		error "(3) Fail to start ost1"

	mount_client $MOUNT || error "(4) Fail to start client!"

	ls -ail $DIR/$tdir > /dev/null 2>&1 && error "(5) ls should fail"

	$START_SCRUB_ON_OST -r || error "(6) Fail to start OI scrub on OST!"

	wait_update_facet ost1 "$LCTL get_param -n \
		osd-*.$(facet_svc ost1).oi_scrub |
		awk '/^status/ { print \\\$2 }'" "completed" 6 ||
		error "(7) Expected '$expected' on ost1"

	ls -ail $DIR/$tdir > /dev/null || error "(8) ls should succeed"
}
run_test 13 "OI scrub can rebuild missed /O entries"

test_14() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] &&
		skip "ldiskfs special test"

	check_mount_and_prep
	$LFS setstripe -c 1 -i 0 $DIR/$tdir

	#define OBD_FAIL_OSD_COMPAT_NO_ENTRY		0x196
	do_facet ost1 $LCTL set_param fail_loc=0x196
	local count=$(precreated_ost_obj_count 0 0)

	createmany -o $DIR/$tdir/f $((count + 1000))
	do_facet ost1 $LCTL set_param fail_loc=0

	umount_client $MOUNT || error "(1) Fail to stop client!"

	stop ost1 || error "(2) Fail to stop ost1"

	echo "run e2fsck"
	run_e2fsck $(facet_host ost1) $(ostdevname 1) "-y" ||
		error "(3) Fail to run e2fsck error"

	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS ||
		error "(4) Fail to start ost1"

	mount_client $MOUNT || error "(5) Fail to start client!"

	local LF_REPAIRED=$($SHOW_SCRUB_ON_OST |
			    awk '/^lf_repa[ir]*ed/ { print $2 }')
	[ $LF_REPAIRED -ge 1000 ] ||
		error "(6) Some entry under /lost+found should be repaired"

	ls -ail $DIR/$tdir > /dev/null || error "(7) ls should succeed"

	stopall

	echo "run e2fsck again after LFSCK"
	run_e2fsck $(facet_host ost1) $(ostdevname 1) "-y" ||
		error "(8) Fail to run e2fsck error"
}
run_test 14 "OI scrub can repair OST objects under lost+found"

test_15() {
	local repaired

	formatall > /dev/null
	setupall > /dev/null

	scrub_prep 20 1
	echo "starting MDTs with OI scrub disabled"
	scrub_start_mds 2 "$MOUNT_OPTS_NOSCRUB"
	scrub_check_status 3 init
	[ "$mds1_FSTYPE" != "ldiskfs" ] ||
		scrub_check_flags 4 recreated,inconsistent

	# run under dryrun mode
	scrub_start 5 --dryrun
	scrub_check_status 6 completed
	if [ "$mds1_FSTYPE" != "ldiskfs" ]; then
		scrub_check_flags 7 inconsistent
		repaired=2
	else
		scrub_check_flags 7 recreated,inconsistent
		repaired=20
	fi
	scrub_check_params 8 dryrun
	scrub_check_repaired 9 $repaired 1

	# run under dryrun mode again
	scrub_start 10 --dryrun
	scrub_check_status 11 completed
	if [ "$mds1_FSTYPE" != "ldiskfs" ]; then
		scrub_check_flags 12 inconsistent
	else
		scrub_check_flags 12 recreated,inconsistent
	fi
	scrub_check_params 13 dryrun
	scrub_check_repaired 14 $repaired 1

	# run under normal mode
	scrub_start 15
	scrub_check_status 16 completed
	scrub_check_flags 17 ""
	scrub_check_params 18 ""
	scrub_check_repaired 19 $repaired 0

	# run under normal mode again
	scrub_start 20
	scrub_check_status 21 completed
	scrub_check_flags 22 ""
	scrub_check_params 23 ""
	scrub_check_repaired 24 0 0
}
run_test 15 "Dryrun mode OI scrub"

test_16() {
	check_mount_and_prep
	scrub_enable_index_backup

	#define OBD_FAIL_OSD_INDEX_CRASH	0x199
	do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param fail_loc=0x199
	scrub_prep 0
	do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param fail_loc=0

	echo "starting MDTs without disabling OI scrub"
	scrub_start_mds 1 "$MOUNT_OPTS_SCRUB"
	mount_client $MOUNT || error "(2) Fail to start client!"
	scrub_check_data 3
	scrub_disable_index_backup
}
run_test 16 "Initial OI scrub can rebuild crashed index objects"

test_17a() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] && skip_env "ldiskfs only test"

#define OBD_FAIL_OSD_OI_ENOSPC				0x19d
	do_facet mds1 $LCTL set_param fail_loc=0x8000019d
	mkdir $DIR/$tdir && error "mkdir should fail"
	stop mds1
	local devname=$(mdsdevname 1)

	stack_trap "start mds1 $devname $MDS_MOUNT_OPTS" EXIT
	FSCK_MAX_ERR=0 run_e2fsck $(facet_active_host mds1) $devname -n ||
		error "e2fsck returned $?"
}
run_test 17a "ENOSPC on OI insert shouldn't leak inodes"

test_17b() {
	[ "$mds1_FSTYPE" != "ldiskfs" ] && skip_env "ldiskfs only test"

#define OBD_FAIL_OSD_DOTDOT_ENOSPC			0x19e
	do_facet mds1 $LCTL set_param fail_loc=0x8000019e
	mkdir $DIR/$tdir && error "mkdir should fail"
	stop mds1
	local devname=$(mdsdevname 1)

	stack_trap "start mds1 $devname $MDS_MOUNT_OPTS" EXIT
	FSCK_MAX_ERR=0 run_e2fsck $(facet_active_host mds1) $devname -n ||
		error "e2fsck returned $?"
}
run_test 17b "ENOSPC on .. insertion shouldn't leak inodes"

test_18() {
	local n
	local fids=()
	local opts=$(csa_add "$MOUNT_OPTS_SCRUB" -o resetoi)

	scrub_prep 10
	scrub_start_mds 1 "$MOUNT_OPTS_SCRUB"
	mount_client $MOUNT || error "(2) Fail to start client!"
	for n in $(seq $MDSCOUNT); do
		fids+=($($LFS path2fid $DIR/$tdir/mds$n/test-framework.sh))
	done
	cleanup_mount $MOUNT > /dev/null || error "(3) Fail to stop client!"
	for n in $(seq $MDSCOUNT); do
		stop mds$n > /dev/null || error "(4) Fail to stop MDS$n!"
	done
	scrub_start_mds 5 "$opts"
	do_facet mds1 dmesg | grep "reset Object Index" ||
		error "(6) reset log not found"
	mount_client $MOUNT || error "(7) Fail to start client!"
	scrub_check_data 7

	local fid
	local path
	for n in $(seq $MDSCOUNT); do
		path=$($LFS fid2path $DIR ${fids[$((n - 1))]})
		[ "$path" == "$DIR/$tdir/mds$n/test-framework.sh" ] ||
			error "path mismatch $path != $DIR/$tdir/mds$n/test-framework.sh"
		fid=$($LFS path2fid $DIR/$tdir/mds$n/test-framework.sh)
		[ "${fids[$((n - 1))]}" == "$fid" ] ||
			error "$DIR/$tdir/mds$n/test-framework.sh FID mismatch ${fids[$((n - 1))]} != $fid"
	done
}
run_test 18 "test mount -o resetoi to recreate OI files"

# restore MDS/OST size
MDSSIZE=${SAVED_MDSSIZE}
OSTSIZE=${SAVED_OSTSIZE}
OSTCOUNT=${SAVED_OSTCOUNT}

# cleanup the system at last
REFORMAT="yes" cleanup_and_setup_lustre

complete $SECONDS
check_and_cleanup_lustre
exit_status
