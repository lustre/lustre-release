#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT="$SANITY_SCRUB_EXCEPT"
[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

[ "${MDSFSTYPE:-$FSTYPE}" != "ldiskfs" ] &&
	skip "test OI scrub only for ldiskfs" && exit 0
require_dsh_mds || exit 0

SAVED_MDSSIZE=${MDSSIZE}
SAVED_OSTSIZE=${OSTSIZE}
# use small MDS + OST size to speed formatting time
# do not use too small MDSSIZE/OSTSIZE, which affect the default journal size
MDSSIZE=100000
OSTSIZE=100000

check_and_setup_lustre
build_test_filter

MDT_DEV="${FSNAME}-MDT0000"
MDT_DEVNAME=$(mdsdevname ${SINGLEMDS//mds/})
SHOW_SCRUB="do_facet $SINGLEMDS \
		$LCTL get_param -n osd-ldiskfs.${MDT_DEV}.oi_scrub"

scrub_prep() {
	local nfiles=$1

	echo "formatall"
	formatall > /dev/null
	echo "setupall"
	setupall > /dev/null

	echo "preparing... ${nfiles} files will be created."
	mkdir -p $DIR/$tdir
	cp $LUSTRE/tests/*.sh $DIR/$tdir/
	[[ $nfiles -gt 0 ]] && { createmany -o $DIR/$tdir/$tfile $nfiles ||
				error "createmany failed"; }

	echo "prepared."
	cleanup_mount $MOUNT > /dev/null || error "Fail to stop client!"
	echo "stop $SINGLEMDS"
	stop $SINGLEMDS > /dev/null || error "Fail to stop MDS!"
}

test_0() {
	scrub_prep 0
	echo "start $SINGLEMDS without disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS > /dev/null ||
		error "(1) Fail to start MDS!"

	local STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "init" ] ||
		error "(2) Expect 'init', but got '$STATUS'"

	local FLAGS=$($SHOW_SCRUB | sed -n '5'p | awk '{print $2}')
	[ -z "$FLAGS" ] || error "(3) Expect empty flags, but got '$FLAGS'"

	mount_client $MOUNT || error "(4) Fail to start client!"

	diff -q $LUSTRE/tests/test-framework.sh $DIR/$tdir/test-framework.sh ||
		error "(5) File diff failed unexpected!"
}
run_test 0 "Do not auto trigger OI scrub for non-backup/restore case"

test_1a() {
	scrub_prep 0
	mds_remove_ois || error "(1) Fail to remove/recreate!"

	echo "start $SINGLEMDS without disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS > /dev/null ||
		error "(2) Fail to start MDS!"

	sleep 3
	local STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "completed" ] ||
		error "(3) Expect 'completed', but got '$STATUS'"

	mount_client $MOUNT || error "(4) Fail to start client!"

	diff -q $LUSTRE/tests/test-framework.sh $DIR/$tdir/test-framework.sh ||
		error "(5) File diff failed unexpected!"
}
run_test 1a "Trigger OI scrub when MDT mounts for OI files remove/recreate case"

test_2() {
	scrub_prep 0
	mds_backup_restore || error "(1) Fail to backup/restore!"

	echo "start $SINGLEMDS without disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS > /dev/null ||
		error "(2) Fail to start MDS!"

	sleep 3
	local STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "completed" ] ||
		error "(3) Expect 'completed', but got '$STATUS'"

	mount_client $MOUNT || error "(4) Fail to start client!"

	diff -q $LUSTRE/tests/test-framework.sh $DIR/$tdir/test-framework.sh ||
		error "(5) File diff failed unexpected!"
}
run_test 2 "Trigger OI scrub when MDT mounts for backup/restore case"

test_3() {
	scrub_prep 0
	mds_backup_restore || error "(1) Fail to backup/restore!"

	echo "start $SINGLEMDS with disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS,noscrub > /dev/null ||
		error "(2) Fail to start MDS!"

	local STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "init" ] ||
		error "(3) Expect 'init', but got '$STATUS'"

	local FLAGS=$($SHOW_SCRUB | sed -n '5'p | awk '{print $2}')
	[ "$FLAGS" == "inconsistent" ] ||
		error "(4) Expect 'inconsistent', but got '$FLAGS'"
	echo "stopall"
	stopall > /dev/null
}
run_test 3 "Do not trigger OI scrub when MDT mounts if 'noscrub' specified"

test_4() {
	scrub_prep 0
	mds_backup_restore || error "(1) Fail to backup/restore!"

	echo "start $SINGLEMDS with disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS,noscrub > /dev/null ||
		error "(2) Fail to start MDS!"

	local STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "init" ] ||
		error "(3) Expect 'init', but got '$STATUS'"

	local FLAGS=$($SHOW_SCRUB | sed -n '5'p | awk '{print $2}')
	[ "$FLAGS" == "inconsistent" ] ||
		error "(4) Expect 'inconsistent', but got '$FLAGS'"

	mount_client $MOUNT || error "(5) Fail to start client!"

	do_facet $SINGLEMDS \
		$LCTL set_param -n osd-ldiskfs.${MDT_DEV}.auto_scrub 1
	diff -q $LUSTRE/tests/test-framework.sh $DIR/$tdir/test-framework.sh ||
		error "(6) File diff failed unexpected!"

	sleep 3
	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "completed" ] ||
		error "(7) Expect 'completed', but got '$STATUS'"
}
run_test 4 "Trigger OI scrub automatically if inconsistent OI mapping was found"

test_5() {
	scrub_prep 1500
	mds_backup_restore || error "(1) Fail to backup/restore!"

	echo "start $SINGLEMDS with disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS,noscrub > /dev/null ||
		error "(2) Fail to start MDS!"

	local STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "init" ] ||
		error "(3) Expect 'init', but got '$STATUS'"

	local FLAGS=$($SHOW_SCRUB | sed -n '5'p | awk '{print $2}')
	[ "$FLAGS" == "inconsistent" ] ||
		error "(4) Expect 'inconsistent', but got '$FLAGS'"

	mount_client $MOUNT || error "(5) Fail to start client!"

	do_facet $SINGLEMDS \
		$LCTL set_param -n osd-ldiskfs.${MDT_DEV}.auto_scrub 1
#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_facet $SINGLEMDS $LCTL set_param fail_val=3
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x190
	diff -q $LUSTRE/tests/test-framework.sh $DIR/$tdir/test-framework.sh ||
		error "(6) File diff failed unexpected!"

	umount_client $MOUNT || error "(7) Fail to stop client!"

	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "scanning" ] ||
		error "(8) Expect 'scanning', but got '$STATUS'"

#define OBD_FAIL_OSD_SCRUB_CRASH	 0x191
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x80000191
	sleep 4
	echo "stop $SINGLEMDS"
	stop $SINGLEMDS > /dev/null || error "(9) Fail to stop MDS!"

	echo "start $SINGLEMDS with disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS,noscrub > /dev/null ||
		error "(10) Fail to start MDS!"

	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "crashed" ] ||
		error "(11) Expect 'crashed', but got '$STATUS'"

	echo "stop $SINGLEMDS"
	stop $SINGLEMDS > /dev/null || error "(12) Fail to stop MDS!"

#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_facet $SINGLEMDS $LCTL set_param fail_val=3
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x190
	echo "start $SINGLEMDS without disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS > /dev/null ||
		error "(13) Fail to start MDS!"

	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "scanning" ] ||
		error "(14) Expect 'scanning', but got '$STATUS'"

#define OBD_FAIL_OSD_SCRUB_FATAL	 0x192
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x80000192
	sleep 4
	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "failed" ] ||
		error "(15) Expect 'failed', but got '$STATUS'"

	mount_client $MOUNT || error "(16) Fail to start client!"

#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_facet $SINGLEMDS $LCTL set_param fail_val=3
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x190
	stat $DIR/$tdir/${tfile}1000 ||
		error "(17) Fail to stat $DIR/$tdir/${tfile}1000!"

	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "scanning" ] ||
		error "(18) Expect 'scanning', but got '$STATUS'"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	do_facet $SINGLEMDS $LCTL set_param fail_val=0
	sleep 5
	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "completed" ] ||
		error "(19) Expect 'completed', but got '$STATUS'"

	FLAGS=$($SHOW_SCRUB | sed -n '5'p | awk '{print $2}')
	[ -z "$FLAGS" ] || error "(20) Expect empty flags, but got '$FLAGS'"
}
run_test 5 "OI scrub state machine"

test_6() {
	scrub_prep 1000
	mds_backup_restore || error "(1) Fail to backup/restore!"

	echo "start $SINGLEMDS with disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS,noscrub > /dev/null ||
		error "(2) Fail to start MDS!"

	local STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "init" ] ||
		error "(3) Expect 'init', but got '$STATUS'"

	local FLAGS=$($SHOW_SCRUB | sed -n '5'p | awk '{print $2}')
	[ "$FLAGS" == "inconsistent" ] ||
		error "(4) Expect 'inconsistent', but got '$FLAGS'"

	mount_client $MOUNT || error "(5) Fail to start client!"

	do_facet $SINGLEMDS \
		$LCTL set_param -n osd-ldiskfs.${MDT_DEV}.auto_scrub 1
#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_facet $SINGLEMDS $LCTL set_param fail_val=3
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x190
	diff -q $LUSTRE/tests/test-framework.sh $DIR/$tdir/test-framework.sh ||
		error "(6) File diff failed unexpected!"

	# Fail the OI scrub to guarantee there is at least on checkpoint
#define OBD_FAIL_OSD_SCRUB_FATAL	 0x192
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x80000192
	sleep 4
	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "failed" ] ||
		error "(7) Expect 'failed', but got '$STATUS'"

#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_facet $SINGLEMDS $LCTL set_param fail_val=3
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x190
	stat $DIR/$tdir/${tfile}800 ||
		error "(8) Fail to stat $DIR/$tdir/${tfile}800!"

	umount_client $MOUNT || error "(9) Fail to stop client!"

	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "scanning" ] ||
		error "(10) Expect 'scanning', but got '$STATUS'"

#define OBD_FAIL_OSD_SCRUB_CRASH	 0x191
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x80000191
	sleep 4
	local POSITION0=$($SHOW_SCRUB | sed -n '11'p | awk '{print $2}')
	POSITION0=$((POSITION0 + 1))

	echo "stop $SINGLEMDS"
	stop $SINGLEMDS > /dev/null || error "(11) Fail to stop MDS!"

#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_facet $SINGLEMDS $LCTL set_param fail_val=3
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x190
	echo "start $SINGLEMDS without disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS > /dev/null ||
		error "(12) Fail to start MDS!"

	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "scanning" ] ||
		error "(13) Expect 'scanning', but got '$STATUS'"

	local POSITION1=$($SHOW_SCRUB | sed -n '10'p |awk '{print $2}')
	[ $POSITION0 -eq $POSITION1 ] ||
		error "(14) Expect position: $POSITION0, but got $POSITION1"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	do_facet $SINGLEMDS $LCTL set_param fail_val=0
	sleep 5
	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "completed" ] ||
		error "(15) Expect 'completed', but got '$STATUS'"

	FLAGS=$($SHOW_SCRUB | sed -n '5'p | awk '{print $2}')
	[ -z "$FLAGS" ] || error "(16) Expect empty flags, but got '$FLAGS'"
}
run_test 6 "OI scrub resumes from last checkpoint"

test_7() {
	scrub_prep 500
	mds_backup_restore || error "(1) Fail to backup/restore!"

	echo "start $SINGLEMDS with disabling OI scrub"
	start $SINGLEMDS $MDT_DEVNAME $MDS_MOUNT_OPTS,noscrub > /dev/null ||
		error "(2) Fail to start MDS!"

	local STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "init" ] ||
		error "(3) Expect 'init', but got '$STATUS'"

	local FLAGS=$($SHOW_SCRUB | sed -n '5'p | awk '{print $2}')
	[ "$FLAGS" == "inconsistent" ] ||
		error "(4) Expect 'inconsistent', but got '$FLAGS'"

	mount_client $MOUNT || error "(5) Fail to start client!"

	do_facet $SINGLEMDS \
		$LCTL set_param -n osd-ldiskfs.${MDT_DEV}.auto_scrub 1
#define OBD_FAIL_OSD_SCRUB_DELAY	 0x190
	do_facet $SINGLEMDS $LCTL set_param fail_val=3
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x190
	diff -q $LUSTRE/tests/test-framework.sh $DIR/$tdir/test-framework.sh ||
		error "(6) File diff failed unexpected!"

	stat $DIR/$tdir/${tfile}300 ||
		error "(7) Fail to stat $DIR/$tdir/${tfile}300!"

	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "scanning" ] ||
		error "(8) Expect 'scanning', but got '$STATUS'"

	FLAGS=$($SHOW_SCRUB | sed -n '5'p | awk '{print $2}')
	[ "$FLAGS" == "inconsistent,auto" ] ||
		error "(9) Expect 'inconsistent,auto', but got '$FLAGS'"

	do_facet $SINGLEMDS $LCTL set_param fail_loc=0
	do_facet $SINGLEMDS $LCTL set_param fail_val=0
	sleep 5
	STATUS=$($SHOW_SCRUB | sed -n '4'p | awk '{print $2}')
	[ "$STATUS" == "completed" ] ||
		error "(10) Expect 'completed', but got '$STATUS'"

	FLAGS=$($SHOW_SCRUB | sed -n '5'p | awk '{print $2}')
	[ -z "$FLAGS" ] || error "(11) Expect empty flags, but got '$FLAGS'"
}
run_test 7 "System is available during OI scrub scanning"

# restore the ${facet}_MKFS_OPTS variables
for facet in MGS MDS OST; do
	opts=SAVED_${facet}_MKFS_OPTS
	if [[ -n ${!opts} ]]; then
		eval ${facet}_MKFS_OPTS=\"${!opts}\"
	fi
done

# restore MDS/OST size
MDSSIZE=${SAVED_MDSSIZE}
OSTSIZE=${SAVED_OSTSIZE}

# cleanup the system at last
formatall

complete $(basename $0) $SECONDS
exit_status
