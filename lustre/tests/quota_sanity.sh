#!/bin/bash

set -e
#set -vx

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH:/sbin
. $SRCDIR/test-framework.sh

LFS=${LFS:-lfs}
LCTL=${LCTL:-lctl}
USER="quota_usr"
TSTID=${TSTID:-60000}
RUNAS=${RUNAS:-"runas -u $TSTID"}
BLK_SZ=1024
BUNIT_SZ=10 # 10 quota blocks
BTUNE_SZ=5  # 5 quota blocks
IUNIT_SZ=10 # 10 files
ITUNE_SZ=5  # 5 files

MOUNT="`cat /proc/mounts | grep "lustre" | awk '{print $2}'`"
if [ -z "$MOUNT" ]; then
	echo "ERROR: lustre not mounted, quit test!"
	exit 1;
fi
OSTCOUNT=`cat /proc/fs/lustre/lov/*/activeobd | head -n 1`
TSTDIR="$MOUNT/quota_dir"

# set_blk_tunables(bunit_sz, btune_sz)
set_blk_tunables() {
	# set bunit and btune size on all obdfilters
	for i in `ls /proc/fs/lustre/obdfilter/*/quota_btune_sz`; do
		echo $(($2 * $BLK_SZ)) > $i
	done
	for i in `ls /proc/fs/lustre/obdfilter/*/quota_bunit_sz`; do
		echo $(($1 * $BLK_SZ)) > $i
	done;
	# set bunit and btune size on mds
	for i in `ls /proc/fs/lustre/mds/mds*/quota_btune_sz`; do
		echo $(($2 * $BLK_SZ)) > $i
	done
	for i in `ls /proc/fs/lustre/mds/mds*/quota_bunit_sz`; do
		echo $(($1 * $BLK_SZ)) > $i
	done
}

# set_file_tunables(iunit_sz, itune_sz)
set_file_tunables() {
	# set iunit and itune size on all obdfilters
	for i in `ls /proc/fs/lustre/obdfilter/*/quota_itune_sz`; do
		echo $2 > $i
	done
	for i in `ls /proc/fs/lustre/obdfilter/*/quota_iunit_sz`; do
		echo $1 > $i
	done;
	# set iunit and itune size on mds
	for i in `ls /proc/fs/lustre/mds/mds*/quota_itune_sz`; do
		echo $2 > $i
	done
	for i in `ls /proc/fs/lustre/mds/mds*/quota_iunit_sz`; do
		echo $1 > $i
	done
}

prepare_test() {
	# create test group
	GRP="`cat /etc/group | grep "$USER" | awk -F: '{print $1}'`"
	if [ -z "$GRP" ]; then
		groupadd -g $TSTID "$USER"
	fi
	TSTID="`cat /etc/group | grep "$USER" | awk -F: '{print $3}'`"

	# create test user
	USR="`cat /etc/passwd | grep "$USER" | awk -F: '{print $1}'`"
	if [ -z "$USR" ]; then
		useradd -u $TSTID -g $TSTID -d /tmp "$USER"
	fi
	
	RUNAS="runas -u $TSTID"
	# set block tunables

	set_blk_tunables $BUNIT_SZ $BTUNE_SZ
	# set file tunaables
	set_file_tunables $IUNIT_SZ $ITUNE_SZ

	[ -d $TSTDIR ] || mkdir $TSTDIR 
	chmod 777 $TSTDIR
}

cleanup_test() {
	# delete test user and group
	userdel "$USER"
	groupdel "$USER"
	
	# restore block tunables to default size
	set_blk_tunables $((1024 * 100)) $((1024 * 50))
	# restore file tunables to default size
	set_file_tunables 5000 2500 

	rm -fr $TSTDIR
}

# set quota
test_1() {
	echo "== Enable quota"
	$LFS quotaoff -ug $MOUNT
	$LFS quotacheck -ug $MOUNT
	return 0
}

# block hard limit (normal use and out of quota)
test_2() {
	echo "== Block hard limit"
	LIMIT=$(( $BUNIT_SZ * $(($OSTCOUNT + 1)) * 10)) # 10 bunits each sever
	TESTFILE="$TSTDIR/quota_tst20"
	
	echo "  User quota (limit: $LIMIT bytes)"
	$LFS setquota -u $USER 0 $LIMIT 0 0 $MOUNT

	$RUNAS touch $TESTFILE >/dev/null 2>&1
	
	echo "    Write ..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) > /dev/null 2>&1 || error "(usr) write failure, but expect success"
	echo "    Done"
	echo "    Write out of block quota ..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) seek=$(($LIMIT/2)) > /dev/null 2>&1
	# flush cache, ensure noquota flag is setted on client
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ seek=$LIMIT > /dev/null 2>&1 && error "(usr) write success, but expect EDQUOT"
	echo "    EDQUOT"

	rm -f $TESTFILE
	
	echo "  Group quota (limit: $LIMIT bytes)"
	$LFS setquota -u $USER 0 0 0 0 $MOUNT		# clear user limit
	$LFS setquota -g $USER 0 $LIMIT 0 0 $MOUNT
	TESTFILE="$TSTDIR/quota_tst21"

	$RUNAS touch $TESTFILE >/dev/null 2>&1

	echo "    Write ..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) > /dev/null 2>&1 || error "(grp) write failure, but expect success"
	echo "    Done"
	echo "    Write out of block quota ..."
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$(($LIMIT/2)) seek=$(($LIMIT/2)) > /dev/null 2>&1
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$TESTFILE bs=$BLK_SZ count=$BUNIT_SZ seek=$LIMIT > /dev/null 2>&1 && error "(grp) write success, but expect EDQUOT"
	echo "    EDQUOT"

	# cleanup
	rm -f $TESTFILE
	$LFS setquota -g $USER 0 0 0 0 $MOUNT
	return 0
}

# file hard limit (normal use and out of quota)
test_3() {
	echo "== File hard limit"
	LIMIT=$(($IUNIT_SZ * 10)) # 10 iunits on mds
	TESTFILE="$TSTDIR/quota_tst30"

	echo "  User quota (limit: $LIMIT files)"
	$LFS setquota -u $USER 0 0 0 $LIMIT $MOUNT

	echo "    Create $LIMIT files ..."
	for i in `seq ${LIMIT}`; do
		$RUNAS touch ${TESTFILE}_$i > /dev/null 2>&1 || error "(usr) touch failure, but except success"
	done
	echo "    Done"
	echo "    Create out of file quota ..."
	$RUNAS touch ${TESTFILE}_xxx > /dev/null 2>&1 && error "(usr) touch success, but expect EDQUOT"
	echo "    EDQUOT"

	for i in `seq ${LIMIT}`; do
		rm -f ${TESTFILE}_$i
	done

	echo "  Group quota (limit: $LIMIT files)"
	$LFS setquota -u $USER 0 0 0 0 $MOUNT		# clear user limit
	$LFS setquota -g $USER 0 0 0 $LIMIT $MOUNT
	TESTFILE="$TSTDIR/quota_tst31"

	echo "    Create $LIMIT files ..."
	for i in `seq ${LIMIT}`; do
		$RUNAS touch ${TESTFILE}_$i > /dev/null 2>&1 || error "(grp) touch failure, but expect success"
	done
	echo "    Done"
	echo "    Create out of file quota ..."
	$RUNAS touch ${TESTFILE}_xxx > /dev/null 2>&1 && error "(grp) touch success, but expect EDQUOT"
	echo "    EDQUOT"

	# cleanup
	for i in `seq ${LIMIT}`; do
		rm -f ${TESTFILE}_$i
	done
	$LFS setquota -g $USER 0 0 0 0 $MOUNT
	return 0
}

# block soft limit (start timer, timer goes off, stop timer)
test_4() {
	echo "== Block soft limit"
	echo "  ** skipped"
	return 0
}

# file soft limit (start timer, timer goes off, stop timer)
test_5() {
	echo "== File soft limit"
	echo "  ** skipped"
	return 0
}

# chown & chgrp (chown & chgrp successfully even out of block/file quota)
test_6() {
	echo "== Chown/Chgrp ignore quota"
	BLIMIT=$(( $BUNIT_SZ * $((OSTCOUNT + 1)) * 10)) # 10 bunits on each server
	ILIMIT=$(( $IUNIT_SZ * 10 )) # 10 iunits on mds
	
	echo "  Set quota limit (0 $BLIMIT 0 $ILIMIT) for $USER.$USER"
	$LFS setquota -u $USER 0 $BLIMIT 0 $ILIMIT $MOUNT
	$LFS setquota -g $USER 0 $BLIMIT 0 $ILIMIT $MOUNT
	
	echo "  Create more than $ILIMIT files and alloc more than $BLIMIT blocks ..."
	for i in `seq $(($ILIMIT + 1))`; do
		touch $TSTDIR/quota_tst60_$i > /dev/null 2>&1 || error "touch failure, expect success"
	done
	dd if=/dev/zero of=$TSTDIR/quota_tst60_1 bs=$BLK_SZ count=$(($BLIMIT+1)) > /dev/null 2>&1 || error "write failure, expect success"

	echo "  Chown files to $USER.$USER ..."
	for i in `seq $(($ILIMIT + 1))`; do
		chown $USER.$USER $TSTDIR/quota_tst60_$i > /dev/null 2>&1 || error "chown failure, but expect success"
	done

	# cleanup
	for i in `seq $(($ILIMIT + 1))`; do
		rm -f $TSTDIR/quota_tst60_$i
	done
	$LFS setquota -u $USER 0 0 0 0 $MOUNT
	$LFS setquota -g $USER 0 0 0 0 $MOUNT
	return 0
}

# block quota acquire & release
test_7() {
	echo "== Block quota acqurie / release"

	if [ $OSTCOUNT -lt 2 ]; then
		echo "WARN: too few osts, skip this test."
		return 0;
	fi

	LIMIT=$(($BUNIT_SZ * $(($OSTCOUNT + 1)) * 10)) # 10 bunits per server
	FILEA="$TSTDIR/quota_tst70_a"
	FILEB="$TSTDIR/quota_tst70_b"
	
	echo "  Set block limit $LIMIT bytes to $USER.$USER"
	$LFS setquota -u $USER 0 $LIMIT 0 0 $MOUNT
	$LFS setquota -g $USER 0 $LIMIT 0 0 $MOUNT

	echo "  Create filea on OST0 and fileb on OST1"
	$LFS setstripe $FILEA 65536 0 1
	$LFS setstripe $FILEB 65536 1 1
	chown $USER.$USER $FILEA
	chown $USER.$USER $FILEB

	echo "  Exceed quota limit ..."
	$RUNAS dd if=/dev/zero of=$FILEB bs=$BLK_SZ count=$(($LIMIT - $BUNIT_SZ * $OSTCOUNT)) >/dev/null 2>&1 || error "write fileb failure, but expect success"
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$FILEB bs=$BLK_SZ seek=$LIMIT count=$BUNIT_SZ >/dev/null 2>&1 && error "write fileb success, but expect EDQUOT"
	sync; sleep 1; sync;
	echo "  Write to OST0 return EDQUOT"
	# this write of OST0 is cache write, will success
	$RUNAS dd if=/dev/zero of=$FILEA bs=$BLK_SZ count=$(($BUNIT_SZ * 2)) >/dev/null 2>&1 || error "write filea failure, but expect success"
	sync; sleep 1; sync;
	$RUNAS dd if=/dev/zero of=$FILEA bs=$BLK_SZ count=$(($BUNIT_SZ * 2)) seek=$(($BUNIT_SZ *2)) >/dev/null 2>&1 && error "write filea success, but expect EDQUOT"
	echo "  EDQUOT"

	echo "  Remove fileb to let OST1 release quota"
	rm -f $FILEB

	echo "  Write to OST0"
	$RUNAS dd if=/dev/zero of=$FILEA bs=$BLK_SZ count=$(($LIMIT - $BUNIT_SZ * $OSTCOUNT)) >/dev/null 2>&1 || error "write filea failure, expect success"
	echo "  Done"

	# cleanup
	rm -f $FILEA
	$LFS setquota -u $USER 0 0 0 0 $MOUNT
	$LFS setquota -g $USER 0 0 0 0 $MOUNT
	return 0
}

# turn off quota
test_8()
{
	echo "=== Turn off quota"
	$LFS quotaoff $MOUNT
	return 0
}
	
prepare_test

# run all tests
for j in `seq 8`; do
	test_$j
	echo "== Done"
	echo " "
done

cleanup_test
