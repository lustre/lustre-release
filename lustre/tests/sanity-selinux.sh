#!/bin/bash
#
# NOTE
# In order to be able to do the runcon commands in test_4,
# the SELinux policy must allow transitions from unconfined_t
# to user_t and guest_t:
# #============= unconfined_r ==============
# allow unconfined_r guest_r;
# allow unconfined_r user_r;
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test:
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-"$SANITY_SELINUX_EXCEPT"}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

SRCDIR=$(dirname $0)
SAVE_PWD=$PWD

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

require_dsh_mds || exit 0

[ "$SLOW" = "no" ] && EXCEPT_SLOW="xxx"

RUNAS_CMD=${RUNAS_CMD:-runas}
# $RUNAS_ID may get set incorrectly somewhere else
[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] &&
	error "RUNAS_ID set to 0, but UID is also 0!"

#
# global variables of this  sanity
#

check_selinux() {
	echo -n "Checking SELinux environment... "
	local selinux_status=$(getenforce)
	if [ "$selinux_status" != "Enforcing" ]; then
	    skip "SELinux is currently in $selinux_status mode," \
		 "but it must be enforced to run sanity-selinux" && exit 0
	fi
	local selinux_policy=$(sestatus |
		awk -F':' '$1 == "Loaded policy name" {print $2}' | xargs)
	if [ -z "$selinux_policy" ]; then
	    selinux_policy=$(sestatus |
		awk -F':' '$1 == "Policy from config file" {print $2}' | xargs)
	fi
	[ "$selinux_policy" == "targeted" ] ||
		error "Accepting only targeted policy"
	echo "$selinux_status, $selinux_policy"
}

check_selinux

# we want double mount
MOUNT_2=${MOUNT_2:-"yes"}
check_and_setup_lustre

rm -rf $DIR/[df][0-9]*

check_runas_id $RUNAS_ID $RUNAS_ID $RUNAS

build_test_filter

umask 077

check_selinux_xattr() {
	local mds=$1
	local mds_path=$2
	local mds_dev=$(facet_device $mds)
	local mntpt="/tmp/mdt_"
	local opts

	do_facet $mds mkdir -p $mntpt  || error "mkdir $mntpt failed"
	mount_fstype $mds $mntpt  || error "mount $mds failed"

	local xattrval=$(do_facet $mds getfattr -n security.selinux \
				${mntpt}/ROOT/$mds_path |
			 awk -F"=" '$1=="security.selinux" {print $2}')

	unmount_fstype $mds $mntpt || error "umount $mds failed"
	do_facet $mds rmdir $mntpt || error "rmdir $mntpt failed"

	echo $xattrval
}


test_1() {
	local devname=$(mdsdevname 1)
	local filename=${DIR}/${tdir}/df1
	local mds_path=${filename#$MOUNT}

	mds_path=${mds_path#/}

	$LFS setdirstripe -i0 -c1 ${DIR}/$tdir || error "create dir $tdir failed"
	touch $filename || error "cannot touch $filename"

	local xattrval=$(check_selinux_xattr "mds1" $mds_path)

	[ -n "$xattrval" -a "$xattrval" != '""' ] ||
		error "security.selinux xattr is not set"
}
run_test 1 "create file and check security.selinux xattr is set on MDT"

test_2a() {
	local devname=$(mdsdevname 1)
	local dirname=${DIR}/${tdir}/dir2a
	local mds_path=${dirname#$MOUNT}

	mds_path=${mds_path#/}

	$LFS setdirstripe -i0 -c1 ${DIR}/$tdir || error "create dir failed"
	mkdir $dirname || error "cannot mkdir $dirname"

	local xattrval=$(check_selinux_xattr "mds1" $mds_path)

	[ -n "$xattrval" -a "$xattrval" != '""' ] ||
		error "security.selinux xattr is not set"
}
run_test 2a "create dir (mkdir) and check security.selinux xattr is set on MDT"

test_2b() {
	local devname=$(mdsdevname 1)
	local dirname1=${DIR}/$tdir/dir2b1
	local dirname2=${DIR}/$tdir/dir2b2
	local mds_path=${dirname1#$MOUNT}

	mds_path=${mds_path#/}

	$LFS setdirstripe -i0 -c1 ${DIR}/$tdir || error "create dir failed"
	$LFS mkdir -c0 $dirname1 || error "cannot 'lfs mkdir' $dirname1"

	local xattrval=$(check_selinux_xattr "mds1" $mds_path)

	mds_path=${dirname2#$MOUNT}
	mds_path=${mds_path#/}

	[ -n "$xattrval" -a "$xattrval" != '""' ] ||
		error "security.selinux xattr is not set"

	$LFS setdirstripe -i0 $dirname2 ||
	    error "cannot 'lfs setdirstripe' $dirname2"

	xattrval=$(check_selinux_xattr "mds1" $mds_path)

	[ -n "$xattrval" -a "$xattrval" != '""' ] ||
		error "security.selinux xattr is not set"
}
run_test 2b "create dir with lfs and check security.selinux xattr is set on MDT"

test_3() {
	local filename=$DIR/$tdir/df3
	local level=$(id -Z | cut -d':' -f4-)
	local unconctx="-u unconfined_u -r unconfined_r -t unconfined_t \
			-l $level"

	mkdir -p $DIR/$tdir
	chmod 777 $DIR/$tdir

	# "access" Lustre
	echo "As unconfined_u: touch $filename"
	$RUNAS_CMD -u $RUNAS_ID runcon $unconctx touch $filename ||
		error "can't touch $filename"
	echo "As unconfined_u: rm -f $filename"
	$RUNAS_CMD -u $RUNAS_ID runcon $unconctx rm -f $filename ||
		error "can't remove $filename"

	return 0
}
run_test 3 "access with unconfined user"

test_4() {
	local filename=$DIR/$tdir/df4
	local guestctx="-u guest_u -r guest_r -t guest_t -l s0"
	local usrctx="-u user_u -r user_r -t user_t -l s0"

	sesearch --role_allow | grep -q "allow unconfined_r user_r"
	if [ $? -ne 0 ]; then
	    skip "SELinux policy module must allow transition from \
		   unconfined_r to user_r for this test." && exit 0
	fi
	sesearch --role_allow | grep -q "allow unconfined_r guest_r"
	if [ $? -ne 0 ]; then
	    skip "SELinux policy module must allow transition from \
		   unconfined_r to guest_r for this test." && exit 0
	fi

	mkdir -p $DIR/$tdir
	chmod 777 $DIR/$tdir

	# "access" Lustre
	echo "As guest_u: touch $filename"
	$RUNAS_CMD -u $RUNAS_ID runcon $guestctx touch $filename &&
		error "touch $filename should have failed"

	# "access" Lustre
	echo "As user_u: touch $filename"
	$RUNAS_CMD -u $RUNAS_ID runcon $usrctx touch $filename ||
		error "can't touch $filename"
	echo "As user_u: rm -f $filename"
	$RUNAS_CMD -u $RUNAS_ID runcon $usrctx rm -f $filename ||
		error "can't remove $filename"

	return 0
}
run_test 4 "access with specific SELinux user"

test_5() {
	local filename=$DIR/df5
	local newsecctx="nfs_t"

	# create file
	touch $filename || error "cannot touch $filename"

	# change sec context
	chcon -t $newsecctx $filename
	ls -lZ $filename

	# purge client's cache
	sync ; echo 3 > /proc/sys/vm/drop_caches

	# get sec context
	ls -lZ $filename
	local secctxseen=$(ls -lZ $filename | awk '{print $4}' | cut -d: -f3)

	[ "$newsecctx" == "$secctxseen" ] ||
		error "sec context seen from 1st mount point is not correct"

	return 0
}
run_test 5 "security context retrieval from MDT xattr"

test_10() {
	local filename1=$DIR/df10
	local filename2=$DIR2/df10
	local newsecctx="nfs_t"

	# create file from 1st mount point
	touch $filename1 || error "cannot touch $filename1"
	ls -lZ $filename1

	# change sec context from 2nd mount point
	chcon -t $newsecctx $filename2
	ls -lZ $filename2

	# get sec context from 1st mount point
	ls -lZ $filename1
	local secctxseen=$(ls -lZ $filename1 | awk '{print $4}' | cut -d: -f3)

	[ "$newsecctx" == "$secctxseen" ] ||
		error_ignore LU-6784 \
		    "sec context seen from 1st mount point is not correct"

	return 0
}
run_test 10 "[consistency] concurrent security context change"

test_20a() {
	local filename1=$DIR/$tdir/df20a
	local filename2=$DIR2/$tdir/df20a
	local req_delay=20
	local unconctx="-u unconfined_u -r unconfined_r -t unconfined_t -l s0"

	mkdir -p $DIR/$tdir
	chmod 777 $DIR/$tdir

	# sleep some time in ll_create_nd()
	#define OBD_FAIL_LLITE_CREATE_FILE_PAUSE   0x1409
	do_facet client "$LCTL set_param fail_val=$req_delay fail_loc=0x1409"

	# create file on first mount point
	$RUNAS_CMD -u $RUNAS_ID runcon $unconctx touch $filename1 &
	local touchpid=$!
	sleep 5

	if [[ -z "$(ps h -o comm -p $touchpid)" ]]; then
		error "touch failed to sleep, pid=$touchpid"
	fi

	# get sec info on second mount point
	if [ -e "$filename2" ]; then
		secinfo2=$(ls -lZ $filename2 | awk '{print $4}')
	fi

	# get sec info on first mount point
	wait $touchpid
	secinfo1=$(ls -lZ $filename1 | awk '{print $4}')

	# compare sec contexts
	[ -z "$secinfo2" -o "$secinfo1" == "$secinfo2" ] ||
		error "sec context seen from 2nd mount point is not correct"

	return 0
}
run_test 20a "[atomicity] concurrent access from another client (file)"

test_20b() {
	local dirname1=$DIR/$tdir/dd20b
	local dirname2=$DIR2/$tdir/dd20b
	local req_delay=20
	local unconctx="-u unconfined_u -r unconfined_r -t unconfined_t -l s0"

	mkdir -p $DIR/$tdir
	chmod 777 $DIR/$tdir

	# sleep some time in ll_create_nd()
	#define OBD_FAIL_LLITE_NEWNODE_PAUSE     0x140a
	do_facet client "$LCTL set_param fail_val=$req_delay fail_loc=0x140a"

	# create file on first mount point
	$RUNAS_CMD -u $RUNAS_ID runcon $unconctx mkdir $dirname1 &
	local mkdirpid=$!
	sleep 5

	if [[ -z "$(ps h -o comm -p $mkdirpid)" ]]; then
		error "mkdir failed to sleep, pid=$mkdirpid"
	fi

	# get sec info on second mount point
	if [ -e "$dirname2" ]; then
		secinfo2=$(ls -ldZ $dirname2 | awk '{print $4}')
	else
		secinfo2=""
	fi

	# get sec info on first mount point
	wait $mkdirpid
	secinfo1=$(ls -ldZ $dirname1 | awk '{print $4}')

	# compare sec contexts
	[ -z "$secinfo2" -o "$secinfo1" == "$secinfo2" ] ||
		error "sec context seen from 2nd mount point is not correct"

	return 0
}
run_test 20b "[atomicity] concurrent access from another client (dir)"

test_20c() {
	local dirname1=$DIR/dd20c
	local dirname2=$DIR2/dd20c
	local req_delay=20

	# sleep some time in ll_create_nd()
	#define OBD_FAIL_LLITE_SETDIRSTRIPE_PAUSE     0x140b
	do_facet client "$LCTL set_param fail_val=$req_delay fail_loc=0x140b"

	# create file on first mount point
	lfs mkdir -c0 $dirname1 &
	local mkdirpid=$!
	sleep 5

	if [[ -z "$(ps h -o comm -p $mkdirpid)" ]]; then
		error "lfs mkdir failed to sleep, pid=$mkdirpid"
	fi

	# get sec info on second mount point
	if [ -e "$dirname2" ]; then
		secinfo2=$(ls -ldZ $dirname2 | awk '{print $4}')
	else
		secinfo2=""
	fi

	# get sec info on first mount point
	wait $mkdirpid
	secinfo1=$(ls -ldZ $dirname1 | awk '{print $4}')

	# compare sec contexts
	[ -z "$secinfo2" -o "$secinfo1" == "$secinfo2" ] ||
		error "sec context seen from 2nd mount point is not correct"

	return 0
}
run_test 20c "[atomicity] concurrent access from another client (dir via lfs)"


complete $SECONDS
check_and_cleanup_lustre
exit_status

