#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT="$SANITY_LSNAPSHOT_EXCEPT"
[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

[[ $(lustre_version_code mds1) -lt $(version_code 2.9.55) ]] ||
[[ $(lustre_version_code ost1) -lt $(version_code 2.9.55) ]] &&
	skip "Need server version at least 2.9.55" && exit 0
[[ $(facet_fstype mds1) = "ldiskfs" ]] ||
[[ $(facet_fstype ost1) = "ldiskfs" ]] &&
	skip "ZFS only test" && exit 0

require_dsh_mds || exit 0
require_dsh_ost || exit 0

check_and_setup_lustre

do_facet mgs $LCTL set_param debug=+snapshot
do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param debug=+snapshot

lss_gen_conf
lss_cleanup
build_test_filter

test_0() {
	echo "Create lss_0_0 with default"
	lsnapshot_create -n lss_0_0 ||
		lss_err "(1) Fail to create lss_0_0 with default"

	echo "List lss_0_0"
	lsnapshot_list -n lss_0_0 ||
		lss_err "(2) Fail to list lss_0_0"

	echo "Create lss_0_1 with barrier off"
	lsnapshot_create -n lss_0_1 --barrier=off ||
		lss_err "(3) Fail to create lss_0_1 with barrier off"

	echo "List lss_0_1"
	lsnapshot_list -n lss_0_1 ||
		lss_err "(4) Fail to list lss_0_1"

	echo "Create lss_0_2 with comment"
	lsnapshot_create -n lss_0_2 -c "'This is test_0'" ||
		lss_err "(5) Fail to create lss_0_2 with comment"

	echo "List lss_0_2"
	lsnapshot_list -n lss_0_2 | grep "This is test_0" ||
		lss_err "(6) Fail to list lss_0_2"

	echo "Create lss_0_2 with barrier on and comment"
	lsnapshot_create -n lss_0_3 --barrier=on -c "'Another one'" ||
		lss_err "(7) Fail to create lss_0_3 with barrier and comment"

	echo "List lss_0_3"
	lsnapshot_list -n lss_0_3 | grep "Another one" ||
		lss_err "(8) Fail to list lss_0_3"

	echo "Try to create lss_0_0 that exist already"
	lsnapshot_create -n lss_0_0 &&
		lss_err "(9) Create snapshot with exist name should fail" ||
		true
}
run_test 0 "create lustre snapshot"

test_1a() {
	mkdir -p $DIR/$tdir || lss_err "(1) Fail to mkdir $DIR/$tdir"
	rm -f $DIR/$tdir/test-framework.sh
	cp $LUSTRE/tests/test-framework.sh $DIR/$tdir/ ||
		lss_err "(2) Fail to copy"

	cancel_lru_locks mdc
	cancel_lru_locks osc

	echo "Create lss_1a_0"
	lsnapshot_create -n lss_1a_0 ||
		lss_err "(3) Fail to create lss_1a_0"

	echo "Check whether mounted (1)"
	lsnapshot_list -n lss_1a_0 -d | grep "mounted" && {
		lsnapshot_list -n lss_1a_0 -d
		lss_err "(4) Expect 'not mount', got 'mounted' for lss_1a_0"
	}

	echo "Mount lss_1a_0"
	lsnapshot_mount -n lss_1a_0 ||
		lss_err "(5) Fail to mount lss_1a_0"

	echo "Check whether mounted (2)"
	local mcount=$(lsnapshot_list -n lss_1a_0 -d | grep "not mount" | wc -l)
	[[ $mcount -ne 0 ]] && {
		if combined_mgs_mds ; then
			lsnapshot_list -n lss_1a_0 -d
			lss_err "(6.1) Got unexpected 'not mount' for lss_1a_0"
		fi

		[[ $mcount -gt 1 ]] && {
			lsnapshot_list -n lss_1a_0 -d
			lss_err "(6.2) Got unexpected 'not mount' for lss_1a_0"
		}

		# The first 10 lines contains and only contains MGS mount status
		lsnapshot_list -n lss_1a_0 -d | head -n 10 |
			grep "not mount" || {
			lsnapshot_list -n lss_1a_0 -d
			lss_err "(6.3) Got unexpected 'not mount' for lss_1a_0"
		}
	}

	local ss_fsname=$(lsnapshot_list -n lss_1a_0 |
			awk '/^snapshot_fsname/ { print $2 }')
	local mntpt="/mnt/$ss_fsname"
	local saved_fsname=$FSNAME

	mkdir -p $mntpt ||
		lss_err "(7) Fail to create mount point $mntpt"
	FSNAME=$ss_fsname
	echo "Mount client"
	mount_client $mntpt ro || {
		FSNAME=$saved_fsname
		lss_err "(8) Fail to mount client for lss_1a_0"
	}

	FSNAME=$saved_fsname
	echo "Check whether the file in snapshot is the same as original one"
	diff $DIR/$tdir/test-framework.sh $mntpt/$tdir/test-framework.sh ||
		lss_err "(9) files should be the same"

	echo "Modify the original file, and check again"
	echo dummy >> $DIR/$tdir/test-framework.sh
	diff $DIR/$tdir/test-framework.sh $mntpt/$tdir/test-framework.sh &&
		lss_err "(10) files should be different"

	umount $mntpt ||
		lss_err "(11) Fail to umount client for lss_1a_0"

	echo "Umount lss_1a_0"
	lsnapshot_umount -n lss_1a_0 ||
		lss_err "(12) Fail to umount lss_1a_0"

	echo "Check whether mounted (3)"
	lsnapshot_list -n lss_1a_0 -d | grep "mounted" && {
		lsnapshot_list -n lss_1a_0 -d
		lss_err "(13) Expect 'not mount', got 'mounted' for lss_1a_0"
	} || true
}
run_test 1a "mount/umount lustre snapshot"

test_1b() {
	echo "Create lss_1b_0"
	lsnapshot_create -n lss_1b_0 ||
		lss_err "(1) Fail to create lss_1b_0"

	echo "Check whether mounted (1)"
	lsnapshot_list -n lss_1b_0 -d | grep "mounted" && {
		lsnapshot_list -n lss_1b_0 -d
		lss_err "(2) Expect 'not mount', got 'mounted' for lss_1b_0"
	}

	stopall || lss_err "(3) Fail to stopall"

	echo "Mount lss_1b_0"
	lsnapshot_mount -n lss_1b_0 ||
		lss_err "(4) Fail to mount lss_1b_0"

	echo "Check whether mounted (2)"
	lsnapshot_list -n lss_1b_0 -d | grep "not mount" && {
		lsnapshot_list -n lss_1b_0 -d
		lss_err "(5) Expect 'mounted', got 'not mount' for lss_1b_0"
	}

	echo "umount lss_1b_0"
	lsnapshot_umount -n lss_1b_0 ||
		lss_err "(6) Fail to umount lss_1b_0"

	echo "Check whether mounted (3)"
	lsnapshot_list -n lss_1b_0 -d | grep "mounted" && {
		lsnapshot_list -n lss_1b_0 -d
		lss_err "(7) Expect 'not mount', got 'mounted' for lss_1b_0"
	}

	setupall || lss_err "(8) Fail to setupall"
}
run_test 1b "mount snapshot without original filesystem mounted"

test_2() {
	echo "Create lss_2_0"
	lsnapshot_create -n lss_2_0 --barrier=off ||
		lss_err "(1) Fail to create lss_2_0"

	echo "List lss_2_0"
	lsnapshot_list -n lss_2_0 ||
		lss_err "(2) Fail to list lss_2_0"

	echo "Destroy lss_2_0"
	lsnapshot_destroy -n lss_2_0 ||
		lss_err "(3) Fail to destroy lss_2_0"

	echo "Try to list lss_2_0 after destroy"
	lsnapshot_list -n lss_2_0 &&
		lss_err "(4) List lss_2_0 should fail after destroy"

	echo "Create lss_2_1"
	lsnapshot_create -n lss_2_1 --barrier=off ||
		lss_err "(5) Fail to create lss_2_1"

	echo "List lss_2_1"
	lsnapshot_list -n lss_2_1 ||
		lss_err "(6) Fail to list lss_2_1"

	echo "Mount lss_2_1"
	lsnapshot_mount -n lss_2_1 ||
		lss_err "(7) Fail to mount lss_2_1"

	echo "Try to destroy lss_2_1 with mounted"
	lsnapshot_destroy -n lss_2_1 &&
		lss_err "(8) Destroy mounted snapshot without -f should fail"

	echo "Destroy lss_2_1 by force with mounted"
	lsnapshot_destroy -n lss_2_1 -f ||
		lss_err "(9) Destroy mounted snapshot with -f should succeed"

	echo "Try to list lss_2_1 after destroy"
	lsnapshot_list -n lss_2_1 &&
		lss_err "(10) List lss_2_1 should fail after destroy" || true
}
run_test 2 "destroy lustre snapshot"

test_3a() {
	echo "Create lss_3a_0"
	lsnapshot_create -n lss_3a_0 --barrier=off -c "'It is test_3a'" ||
		lss_err "(1) Fail to create lss_3a_0"

	echo "List lss_3a_0"
	lsnapshot_list -n lss_3a_0 ||
		lss_err "(2) Fail to list lss_3a_0"

	local old_mtime=$(lsnapshot_list -n lss_3a_0 |
			awk '/^modify_time/ { $1=""; print $0 }')

	echo "Rename lss_3a_0 to lss_3a_1"
	lsnapshot_modify -n lss_3a_0 -N "lss_3a_1" ||
		lss_err "(3) Fail to rename lss_3a_0 to lss_3a_1"

	echo "Try to list lss_3a_0 after rename"
	lsnapshot_list -n lss_3a_0 &&
		lss_err "(4) List lss_3a_0 should fail after rename"

	echo "List lss_3a_1"
	lsnapshot_list -n lss_3a_1 ||
		lss_err "(5) Fail to list lss_3a_1"

	local new_mtime=$(lsnapshot_list -n lss_3a_1 |
			awk '/^modify_time/ { $1=""; print $0 }')
	echo "Check whether mtime has been changed"
	[ "$old_mtime" != "$new_mtime" ] ||
		lss_err "(6) mtime should be changed because of rename"

	echo "Modify lss_3a_1's comment"
	lsnapshot_modify -n lss_3a_1 -c "'Renamed from lss_3a_0'" ||
		lss_err "(7) Fail to change lss_3a_1's comment"

	echo "Check whether comment has been changed"
	lsnapshot_list -n lss_3a_1 -d | grep "It is test_3a" && {
		lsnapshot_list -n lss_3a_1 -d
		lss_err "(8) The comment should have been changed"
	}

	echo "Modify lss_3a_1's name and comment together"
	lsnapshot_modify -n lss_3a_1 -N "lss_3a_2" -c "'Change again'" ||
		lss_err "(9) Fail to modify lss_3a_1"

	echo "Mount lss_3a_2"
	lsnapshot_mount -n lss_3a_2 ||
		lss_err "(10) Fail to mount lss_3a_2"

	echo "Try to rename lss_3a_2 to lss_3a_3 with mounted"
	lsnapshot_modify -n lss_3a_2 -N "lss_3a_3" &&
		lss_err "(11) Rename mounted snapshot lss_3a_2 should fail"

	echo "Modify lss_3a_2's comment with mounted"
	lsnapshot_modify -n lss_3a_2 -c "'Change comment with mounted'" ||
		lss_err "(12) Change comment with mount should succeed"

	echo "Umount lss_3a_2"
	lsnapshot_umount -n lss_3a_2 ||
		lss_err "(13) Fail to umount lss_3a_2"
}
run_test 3a "modify lustre snapshot"

test_3b() {
	echo "Create lss_3b_0"
	lsnapshot_create -n lss_3b_0 --barrier=off -c "'It is test_3b'" ||
		lss_err "(1) Fail to create lss_3b_0"

	echo "List lss_3b_0"
	lsnapshot_list -n lss_3b_0 ||
		lss_err "(2) Fail to list lss_3b_0"

	stopall || lss_err "(3) Fail to stopall"

	echo "Modify lss_3b_0's name and comment together"
	lsnapshot_modify -n lss_3b_0 -N "lss_3b_1" -c "'Change again'" ||
		lss_err "(4) Fail to modify lss_3b_0"

	echo "Try to list lss_3b_0 after rename"
	lsnapshot_list -n lss_3b_0 &&
		lss_err "(5) List lss_3b_0 should fail after rename"

	echo "Check whether comment has been changed"
	lsnapshot_list -n lss_3b_1 -d | grep "It is test_3b" && {
		lsnapshot_list -n lss_3b_1 -d
		lss_err "(6) The comment should have been changed"
	}

	setupall || lss_err "(7) Fail to setupall"
}
run_test 3b "modify snapshot without original filesystem mounted"

lss_cleanup
do_facet mgs $LCTL set_param debug=-snapshot
do_nodes $(comma_list $(mdts_nodes)) $LCTL set_param debug=-snapshot
complete $SECONDS
check_and_cleanup_lustre
exit_status
