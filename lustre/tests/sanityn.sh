#!/bin/bash

set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 3192 LU-1205 15528/3811 16929 9977 15528/11549 18080
ALWAYS_EXCEPT="                14b  18c     19         22    28   29          35    $SANITYN_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# bug number for skipped test:        12652 12652
grep -q 'Enterprise Server 10' /etc/SuSE-release 2> /dev/null &&
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 11    14" || true

# It will be ported soon.
EXCEPT="$EXCEPT 22"

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

SIZE=${SIZE:-40960}
CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
OPENFILE=${OPENFILE:-openfile}
OPENUNLINK=${OPENUNLINK:-openunlink}
export MULTIOP=${MULTIOP:-multiop}
export TMP=${TMP:-/tmp}
MOUNT_2=${MOUNT_2:-"yes"}
CHECK_GRANT=${CHECK_GRANT:-"yes"}
GRANT_CHECK_LIST=${GRANT_CHECK_LIST:-""}

SAVE_PWD=$PWD

export NAME=${NAME:-local}

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
CLEANUP=${CLEANUP:-:}
SETUP=${SETUP:-:}
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

if [ $(facet_fstype $SINGLEMDS) = "zfs" ]; then
# bug number for skipped test:        LU-2189 LU-2776
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 36      51a"
# LU-2829 / LU-2887 - make allowances for ZFS slowness
	TEST33_NFILES=${TEST33_NFILES:-1000}
fi

[ "$SLOW" = "no" ] && EXCEPT_SLOW="33a"

FAIL_ON_ERROR=false

SETUP=${SETUP:-:}
TRACE=${TRACE:-""}

check_and_setup_lustre

LOVNAME=$($LCTL get_param -n llite.*.lov.common_name | tail -n 1)
OSTCOUNT=$($LCTL get_param -n lov.$LOVNAME.numobd)

assert_DIR
rm -rf $DIR1/[df][0-9]* $DIR1/lnk $DIR/[df].${TESTSUITE}*

SAMPLE_FILE=$TMP/$(basename $0 .sh).junk
dd if=/dev/urandom of=$SAMPLE_FILE bs=1M count=1

# $RUNAS_ID may get set incorrectly somewhere else
[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] && error "\$RUNAS_ID set to 0, but \$UID is also 0!"

check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

build_test_filter

mkdir -p $MOUNT2
mount_client $MOUNT2

test_1a() {
	touch $DIR1/f1
	[ -f $DIR2/f1 ] || error
}
run_test 1a "check create on 2 mtpt's =========================="

test_1b() {
	chmod 777 $DIR2/f1
	$CHECKSTAT -t file -p 0777 $DIR1/f1 || error
	chmod a-x $DIR2/f1
}
run_test 1b "check attribute updates on 2 mtpt's ==============="

test_1c() {
	$CHECKSTAT -t file -p 0666 $DIR1/f1 || error
}
run_test 1c "check after remount attribute updates on 2 mtpt's ="

test_1d() {
	rm $DIR2/f1
	$CHECKSTAT -a $DIR1/f1 || error
}
run_test 1d "unlink on one mountpoint removes file on other ===="

test_2a() {
	touch $DIR1/f2a
	ls -l $DIR2/f2a
	chmod 777 $DIR2/f2a
	$CHECKSTAT -t file -p 0777 $DIR1/f2a || error
}
run_test 2a "check cached attribute updates on 2 mtpt's ========"

test_2b() {
	touch $DIR1/f2b
	ls -l $DIR2/f2b
	chmod 777 $DIR1/f2b
	$CHECKSTAT -t file -p 0777 $DIR2/f2b || error
}
run_test 2b "check cached attribute updates on 2 mtpt's ========"

# NEED TO SAVE ROOT DIR MODE
test_2c() {
	chmod 777 $DIR1
	$CHECKSTAT -t dir -p 0777 $DIR2 || error
}
run_test 2c "check cached attribute updates on 2 mtpt's root ==="

test_2d() {
	chmod 755 $DIR1
	$CHECKSTAT -t dir -p 0755 $DIR2 || error
}
run_test 2d "check cached attribute updates on 2 mtpt's root ==="

test_2e() {
        chmod 755 $DIR1
        ls -l $DIR1
        ls -l $DIR2
        chmod 777 $DIR1
        $RUNAS dd if=/dev/zero of=$DIR2/$tfile count=1 || error
}
run_test 2e "check chmod on root is propagated to others"

test_2f() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	local MDTIDX=1
	local remote_dir=$tdir/remote_dir

	mkdir -p $DIR1/$tdir
	$LFS mkdir -i $MDTIDX $DIR1/$remote_dir ||
	           error "Create remote directory failed"

	touch $DIR1/$remote_dir/$tfile ||
		error "Create file under remote directory failed"
	chmod 777 $DIR1/$remote_dir/$tfile ||
		error "Chmod file under remote directory failed"

	$CHECKSTAT -t file -p 0777 $DIR2/$remote_dir/$tfile ||
		error "Check attr of file under remote directory failed"

	chown $RUNAS_ID:$RUNAS_GID $DIR1/$remote_dir/$tfile ||
		error "Chown file under remote directory failed"

	$CHECKSTAT -u \#$RUNAS_ID -g \#$RUNAS_GID $DIR2/$remote_dir/$tfile ||
		error "Check owner of file under remote directory failed"

	cd $DIR2/$remote_dir || error "enter remote dir"
	rm -rf $DIR1/$remote_dir/$tfile ||
		error "Unlink remote directory failed"

	$CHECKSTAT -t file $DIR2/$remote_dir/$tfile &&
		error "unlink file still exists!"

        cd $DIR2/$tdir || error "exit remote dir"
	rm -rf $DIR1/$tdir || error "unlink directory failed"
}
run_test 2f "check attr/owner updates on DNE with 2 mtpt's"

test_3() {
	local target="this/is/good"
	ln -s $target $DIR1/$tfile || error "ln -s $target $DIR1/$tfile failed"
	[ "$(ls -l $DIR2/$tfile | sed -e 's/.* -> //')" = "$target" ] ||
		error "link $DIR2/$tfile not as expected"
}
run_test 3 "symlink on one mtpt, readlink on another ==========="

test_4() {
	multifstat $DIR1/f4 $DIR2/f4
}
run_test 4 "fstat validation on multiple mount points =========="

test_5() {
	mcreate $DIR1/f5
	$TRUNCATE $DIR2/f5 100
	$CHECKSTAT -t file -s 100 $DIR1/f5 || error
	rm $DIR1/f5
}
run_test 5 "create a file on one mount, truncate it on the other"

test_6() {
	openunlink $DIR1/$tfile $DIR2/$tfile || \
		error "openunlink $DIR1/$tfile $DIR2/$tfile"
}
run_test 6 "remove of open file on other node =================="

test_7() {
	local dir=d7
	opendirunlink $DIR1/$dir $DIR2/$dir || \
		error "opendirunlink $DIR1/$dir $DIR2/$dir"
}
run_test 7 "remove of open directory on other node ============="

test_8() {
	opendevunlink $DIR1/$tfile $DIR2/$tfile || \
		error "opendevunlink $DIR1/$tfile $DIR2/$tfile"
}
run_test 8 "remove of open special file on other node =========="

test_9() {
	MTPT=1
	local dir
	> $DIR2/f9
	for C in a b c d e f g h i j k l; do
		dir=`eval echo \\$DIR$MTPT`
		echo -n $C >> $dir/f9
		[ "$MTPT" -eq 1 ] && MTPT=2 || MTPT=1
	done
	[ "`cat $DIR1/f9`" = "abcdefghijkl" ] || \
		error "`od -a $DIR1/f9` != abcdefghijkl"
}
run_test 9 "append of file with sub-page size on multiple mounts"

test_10a() {
	MTPT=1
	local dir
	OFFSET=0
	> $DIR2/f10
	for C in a b c d e f g h i j k l; do
		dir=`eval echo \\$DIR$MTPT`
		echo -n $C | dd of=$dir/f10 bs=1 seek=$OFFSET count=1
		[ "$MTPT" -eq 1 ] && MTPT=2 || MTPT=1
		OFFSET=`expr $OFFSET + 1`
	done
	[ "`cat $DIR1/f10`" = "abcdefghijkl" ] || \
		error "`od -a $DIR1/f10` != abcdefghijkl"
}
run_test 10a "write of file with sub-page size on multiple mounts "

test_10b() {
	# create a seed file
	yes "R" | head -c 4000 >$TMP/f10b-seed
	dd if=$TMP/f10b-seed of=$DIR1/f10b bs=3k count=1 || error "dd $DIR1"

	$TRUNCATE $DIR1/f10b 4096 || error "truncate 4096"

	dd if=$DIR2/f10b of=$TMP/f10b-lustre bs=4k count=1 || error "dd $DIR2"

	# create a test file locally to compare
	dd if=$TMP/f10b-seed of=$TMP/f10b bs=3k count=1 || error "dd random"
	$TRUNCATE $TMP/f10b 4096 || error "truncate 4096"
	cmp $TMP/f10b $TMP/f10b-lustre || error "file miscompare"
	rm $TMP/f10b $TMP/f10b-lustre $TMP/f10b-seed
}
run_test 10b "write of file with sub-page size on multiple mounts "

test_11() {
	test_mkdir $DIR1/d11
	multiop_bg_pause $DIR1/d11/f O_c || return 1
	MULTIPID=$!
	cp -p /bin/ls $DIR1/d11/f
	$DIR2/d11/f
	RC=$?
	kill -USR1 $MULTIPID
	wait $MULTIPID || error
	[ $RC -eq 0 ] && error || true
}
run_test 11 "execution of file opened for write should return error ===="

test_12() {
       DIR=$DIR DIR2=$DIR2 sh lockorder.sh
}
run_test 12 "test lock ordering (link, stat, unlink) ==========="

test_13() {	# bug 2451 - directory coherency
	test_mkdir $DIR1/d13 || error
       cd $DIR1/d13 || error
       ls
       ( touch $DIR1/d13/f13 ) # needs to be a separate shell
       ls
       rm -f $DIR2/d13/f13 || error
       ls 2>&1 | grep f13 && error "f13 shouldn't return an error (1)" || true
       # need to run it twice
       ( touch $DIR1/d13/f13 ) # needs to be a separate shell
       ls
       rm -f $DIR2/d13/f13 || error
       ls 2>&1 | grep f13 && error "f13 shouldn't return an error (2)" || true
}
run_test 13 "test directory page revocation ===================="

test_14() {
	test_mkdir -p $DIR1/$tdir
	cp -p /bin/ls $DIR1/$tdir/$tfile
	multiop_bg_pause $DIR1/$tdir/$tfile Ow_c || return 1
	MULTIPID=$!

	$DIR2/$tdir/$tfile && error || true
	kill -USR1 $MULTIPID
	wait $MULTIPID || return 2
}
run_test 14 "execution of file open for write returns -ETXTBSY ="

test_14a() {
	test_mkdir -p $DIR1/d14
	cp -p `which multiop` $DIR1/d14/multiop || error "cp failed"
        MULTIOP_PROG=$DIR1/d14/multiop multiop_bg_pause $TMP/test14.junk O_c || return 1
        MULTIOP_PID=$!
        $MULTIOP $DIR2/d14/multiop Oc && error "expected error, got success"
        kill -USR1 $MULTIOP_PID || return 2
        wait $MULTIOP_PID || return 3
        rm $TMP/test14.junk $DIR1/d14/multiop || error "removing multiop"
}
run_test 14a "open(RDWR) of executing file returns -ETXTBSY ===="

test_14b() { # bug 3192, 7040
	test_mkdir -p $DIR1/d14
	cp -p `which multiop` $DIR1/d14/multiop || error "cp failed"
        MULTIOP_PROG=$DIR1/d14/multiop multiop_bg_pause $TMP/test14.junk O_c || return 1
        MULTIOP_PID=$!
        $TRUNCATE $DIR2/d14/multiop 0 && kill -9 $MULTIOP_PID && \
		error "expected truncate error, got success"
        kill -USR1 $MULTIOP_PID || return 2
        wait $MULTIOP_PID || return 3
	cmp `which multiop` $DIR1/d14/multiop || error "binary changed"
	rm $TMP/test14.junk $DIR1/d14/multiop || error "removing multiop"
}
run_test 14b "truncate of executing file returns -ETXTBSY ======"

test_14c() { # bug 3430, 7040
	test_mkdir -p $DIR1/d14
	cp -p `which multiop` $DIR1/d14/multiop || error "cp failed"
	MULTIOP_PROG=$DIR1/d14/multiop multiop_bg_pause $TMP/test14.junk O_c || return 1
        MULTIOP_PID=$!
	cp /etc/hosts $DIR2/d14/multiop && error "expected error, got success"
	kill -USR1 $MULTIOP_PID || return 2
	wait $MULTIOP_PID || return 3
	cmp `which multiop` $DIR1/d14/multiop || error "binary changed"
	rm $TMP/test14.junk $DIR1/d14/multiop || error "removing multiop"
}
run_test 14c "open(O_TRUNC) of executing file return -ETXTBSY =="

test_14d() { # bug 10921
	test_mkdir -p $DIR1/d14
	cp -p `which multiop` $DIR1/d14/multiop || error "cp failed"
	MULTIOP_PROG=$DIR1/d14/multiop multiop_bg_pause $TMP/test14.junk O_c || return 1
        MULTIOP_PID=$!
	log chmod
	chmod 600 $DIR1/d14/multiop || error "chmod failed"
	kill -USR1 $MULTIOP_PID || return 2
	wait $MULTIOP_PID || return 3
	cmp `which multiop` $DIR1/d14/multiop || error "binary changed"
	rm $TMP/test14.junk $DIR1/d14/multiop || error "removing multiop"
}
run_test 14d "chmod of executing file is still possible ========"

test_15() {	# bug 974 - ENOSPC
	echo "PATH=$PATH"
	sh oos2.sh $MOUNT1 $MOUNT2
	wait_delete_completed
	grant_error=`dmesg | grep "> available"`
	[ -z "$grant_error" ] || error "$grant_error"
}
run_test 15 "test out-of-space with multiple writers ==========="

COUNT=${COUNT:-2500}
# The FSXNUM reduction for ZFS is needed until ORI-487 is fixed.
# We don't want to skip it entirely, but ZFS is VERY slow and cannot
# pass a 2500 operation dual-mount run within the time limit.
if [ "$(facet_fstype ost1)" = "zfs" ]; then
	FSXNUM=$((COUNT / 5))
	FSXP=1
elif [ "$SLOW" = "yes" ]; then
	FSXNUM=$((COUNT * 5))
	FSXP=500
else
	FSXNUM=$COUNT
	FSXP=100
fi

test_16() {
	local file1=$DIR1/$tfile
	local file2=$DIR2/$tfile

	# to allocate grant because it may run out due to test_15.
	lfs setstripe -c -1 $file1
	dd if=/dev/zero of=$file1 bs=$STRIPE_BYTES count=$OSTCOUNT oflag=sync
	dd if=/dev/zero of=$file2 bs=$STRIPE_BYTES count=$OSTCOUNT oflag=sync
	rm -f $file1

	lfs setstripe -c -1 $file1 # b=10919
	fsx -c 50 -p $FSXP -N $FSXNUM -l $((SIZE * 256)) -S 0 $file1 $file2
}
run_test 16 "$FSXNUM iterations of dual-mount fsx"

test_17() { # bug 3513, 3667
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	lfs setstripe $DIR1/$tfile -i 0 -c 1
	cp $SAMPLE_FILE $DIR1/$tfile
	cancel_lru_locks osc > /dev/null
	#define OBD_FAIL_ONCE|OBD_FAIL_LDLM_CREATE_RESOURCE    0x30a
	do_facet ost1 lctl set_param fail_loc=0x8000030a
	ls -ls $DIR1/$tfile | awk '{ print $1,$6 }' > $DIR1/$tfile-1 & \
	ls -ls $DIR2/$tfile | awk '{ print $1,$6 }' > $DIR2/$tfile-2
	wait
	diff -u $DIR1/$tfile-1 $DIR2/$tfile-2 || error "files are different"
}
run_test 17 "resource creation/LVB creation race ==============="

test_18() {
        # turn e.g. ALWAYS_EXCEPT="18c" into "-e 3"
        local idx
        local excepts=
        for idx in {a..z}; do
                local ptr=EXCEPT_ALWAYS_18$idx
                [ x${!ptr} = xtrue ] || continue

                excepts="$excepts -e $(($(printf %d \'$idx)-96))"
        done

	$LUSTRE/tests/mmap_sanity -d $MOUNT1 -m $MOUNT2 $excepts
	sync; sleep 1; sync
}
run_test 18 "mmap sanity check ================================="

test_19() { # bug3811
	local node=$(facet_active_host ost1)

	# check whether obdfilter is cache capable at all
	if ! get_osd_param $node '' read_cache_enable >/dev/null; then
		echo "not cache-capable obdfilter"
		return 0
	fi

	local MAX=$(get_osd_param $node '' readcache_max_filesize | \
		    head -n 1)
	set_osd_param $node '' readcache_max_filesize 4096
	dd if=/dev/urandom of=$TMP/$tfile bs=512k count=32
	local SUM=$(cksum $TMP/$tfile | cut -d" " -f 1,2)
	cp $TMP/$tfile $DIR1/$tfile
	for i in `seq 1 20`; do
		[ $((i % 5)) -eq 0 ] && log "$testname loop $i"
		cancel_lru_locks osc > /dev/null
		cksum $DIR1/$tfile | cut -d" " -f 1,2 > $TMP/sum1 & \
		cksum $DIR2/$tfile | cut -d" " -f 1,2 > $TMP/sum2
		wait
		[ "$(cat $TMP/sum1)" = "$SUM" ] || \
			error "$DIR1/$tfile $(cat $TMP/sum1) != $SUM"
		[ "$(cat $TMP/sum2)" = "$SUM" ] || \
			error "$DIR2/$tfile $(cat $TMP/sum2) != $SUM"
	done
	set_osd_param $node '' readcache_max_filesize $MAX
	rm $DIR1/$tfile
}
run_test 19 "test concurrent uncached read races ==============="

test_20() {
	test_mkdir $DIR1/d20
	cancel_lru_locks osc
	CNT=$((`lctl get_param -n llite.*.dump_page_cache | wc -l`))
	$MULTIOP $DIR1/f20 Ow8190c
	$MULTIOP $DIR2/f20 Oz8194w8190c
	$MULTIOP $DIR1/f20 Oz0r8190c
	cancel_lru_locks osc
	CNTD=$((`lctl get_param -n llite.*.dump_page_cache | wc -l` - $CNT))
	[ $CNTD -gt 0 ] && \
	    error $CNTD" page left in cache after lock cancel" || true
}
run_test 20 "test extra readahead page left in cache ===="

cleanup_21() {
	trap 0
	umount $DIR1/$tdir
}

test_21() { # Bug 5907
	test_mkdir $DIR1/$tdir
	mount /etc $DIR1/$tdir --bind || error "mount failed" # Poor man's mount.
	trap cleanup_21 EXIT
	rmdir -v $DIR1/$tdir && error "Removed mounted directory"
	rmdir -v $DIR2/$tdir && echo "Removed mounted directory from another mountpoint, needs to be fixed"
	test -d $DIR1/$tdir || error "Mounted directory disappeared"
	cleanup_21
	test -d $DIR2/$tdir || test -d $DIR1/$tdir && error "Removed dir still visible after umount"
	true
}
run_test 21 " Try to remove mountpoint on another dir ===="

test_23() { # Bug 5972
	local at_diff=$(do_facet $SINGLEMDS \
		$LCTL get_param -n mdd.*MDT0000*.atime_diff | head -n1)
	echo "atime should be updated while another read" > $DIR1/$tfile

	# clear the lock(mode: LCK_PW) gotten from creating operation
	cancel_lru_locks osc
	time1=$(date +%s)
	echo "now is $time1"
	sleep $((at_diff + 1))

	echo "starting reads"
	multiop_bg_pause $DIR1/$tfile or20_c || return 1
        # with SOM and opencache enabled, we need to close a file and cancel
        # open lock to get atime propogated to MDS
        kill -USR1 $! || return 2
        cancel_lru_locks mdc

	time2=$(stat -c "%X" $DIR/$tfile)
	echo "new atime is $time2"

	[ $time2 -gt $time1 ] || error "atime was not updated"
	rm -f $DIR1/$tfile || error "rm -f $DIR1/$tfile failed"
	true
}
run_test 23 " others should see updated atime while another read===="

test_24a() {
	touch $DIR1/$tfile
	lfs df || error "lfs df failed"
	lfs df -ih || error "lfs df -ih failed"
	lfs df -h $DIR1 || error "lfs df -h $DIR1 failed"
	lfs df -i $DIR2 || error "lfs df -i $DIR2 failed"
	lfs df $DIR1/$tfile || error "lfs df $DIR1/$tfile failed"
	lfs df -ih $DIR2/$tfile || error "lfs df -ih $DIR2/$tfile failed"

	OSC=`lctl dl | awk '/-osc-|OSC.*MNT/ {print $4}' | head -n 1`
#	OSC=`lctl dl | awk '/-osc-/ {print $4}' | head -n 1`
	lctl --device %$OSC deactivate
	lfs df -i || error "lfs df -i with deactivated OSC failed"
	lctl --device %$OSC activate
	lfs df || error "lfs df with reactivated OSC failed"
}
run_test 24a "lfs df [-ih] [path] test ========================="

test_24b() {
	touch $DIR1/$tfile
	fsnum=$(lfs_df | grep -c "summary")
	[ $fsnum -eq 2 ] || error "lfs df shows $fsnum != 2 filesystems."
}
run_test 24b "lfs df should show both filesystems ==============="

test_25a() {
	local acl=$(lctl get_param -n mdc.*MDT0000-mdc-*.connect_flags |
								grep -c acl)
	[ "$acl" -lt 1 ] && skip "must have acl, skipping" && return

	mkdir -p $DIR1/$tdir
	touch $DIR1/$tdir/f1 || error "touch $DIR1/$tdir/f1"
	chmod 0755 $DIR1/$tdir/f1 || error "chmod 0755 $DIR1/$tdir/f1"

	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 || error "checkstat $DIR2/$tdir/f1 #1"
	setfacl -m u:$RUNAS_ID:--- -m g:$RUNAS_GID:--- $DIR1/$tdir ||
		error "setfacl $DIR2/$tdir #1"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 && error "checkstat $DIR2/$tdir/f1 #2"
	setfacl -m u:$RUNAS_ID:r-x -m g:$RUNAS_GID:r-x $DIR1/$tdir ||
		error "setfacl $DIR2/$tdir #2"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 || error "checkstat $DIR2/$tdir/f1 #3"
	setfacl -m u:$RUNAS_ID:--- -m g:$RUNAS_GID:--- $DIR1/$tdir ||
		error "setfacl $DIR2/$tdir #3"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 && error "checkstat $DIR2/$tdir/f1 #4"
	setfacl -x u:$RUNAS_ID: -x g:$RUNAS_GID: $DIR1/$tdir ||
		error "setfacl $DIR2/$tdir #4"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 || error "checkstat $DIR2/$tdir/f1 #5"

	rm -rf $DIR1/$tdir
}
run_test 25a "change ACL on one mountpoint be seen on another ==="

test_25b() {
	local acl=$(lctl get_param -n mdc.*MDT0000-mdc-*.connect_flags |
							grep -c acl)
	[ "$acl" -lt 1 ] && skip "must have acl, skipping" && return

	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	rm -rf $DIR1/$tdir
	$LFS mkdir -i 1 $DIR1/$tdir
	touch $DIR1/$tdir/f1 || error "touch $DIR1/$tdir/f1"
	chmod 0755 $DIR1/$tdir/f1 || error "chmod 0755 $DIR1/$tdir/f1"

	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 || error "checkstat $DIR2/$tdir/f1 #1"
	setfacl -m u:$RUNAS_ID:--- -m g:$RUNAS_GID:--- $DIR1/$tdir ||
		error "setfacl $DIR2/$tdir #1"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 && error "checkstat $DIR2/$tdir/f1 #2"
	setfacl -m u:$RUNAS_ID:r-x -m g:$RUNAS_GID:r-x $DIR1/$tdir ||
		error "setfacl $DIR2/$tdir #2"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 || error "checkstat $DIR2/$tdir/f1 #3"
	setfacl -m u:$RUNAS_ID:--- -m g:$RUNAS_GID:--- $DIR1/$tdir ||
		error "setfacl $DIR2/$tdir #3"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 && error "checkstat $DIR2/$tdir/f1 #4"
	setfacl -x u:$RUNAS_ID: -x g:$RUNAS_GID: $DIR1/$tdir ||
		error "setfacl $DIR2/$tdir #4"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 || error "checkstat $DIR2/$tdir/f1 #5"

	rm -rf $DIR1/$tdir
}
run_test 25b "change ACL under remote dir on one mountpoint be seen on another"

test_26a() {
        utime $DIR1/f26a -s $DIR2/f26a || error
}
run_test 26a "allow mtime to get older"

test_26b() {
        touch $DIR1/$tfile
        sleep 1
        echo "aaa" >> $DIR1/$tfile
        sleep 1
        chmod a+x $DIR2/$tfile
        mt1=`stat -c %Y $DIR1/$tfile`
        mt2=`stat -c %Y $DIR2/$tfile`

        if [ x"$mt1" != x"$mt2" ]; then
                error "not equal mtime, client1: "$mt1", client2: "$mt2"."
        fi
}
run_test 26b "sync mtime between ost and mds"

test_27() {
	cancel_lru_locks osc
	lctl clear
	dd if=/dev/zero of=$DIR2/$tfile bs=$((4096+4))k conv=notrunc count=4 seek=3 &
	DD2_PID=$!
	usleep 50
	log "dd 1 started"

	dd if=/dev/zero of=$DIR1/$tfile bs=$((16384-1024))k conv=notrunc count=1 seek=4 &
	DD1_PID=$!
	log "dd 2 started"

	sleep 1
	dd if=/dev/zero of=$DIR1/$tfile bs=8k conv=notrunc count=1 seek=0
	log "dd 3 finished"
	lctl set_param -n ldlm.dump_namespaces ""
	wait $DD1_PID $DD2_PID
	[ $? -ne 0 ] && lctl dk $TMP/debug || true
}
run_test 27 "align non-overlapping extent locks from request ==="

test_28() { # bug 9977
	ECHO_UUID="ECHO_osc1_UUID"
	tOST=$($LCTL dl | awk '/-osc-|OSC.*MNT/ { print $4 }' | head -n1)

	$LFS setstripe $DIR1/$tfile -S 1048576 -i 0 -c 2
	tOBJID=`$LFS getstripe $DIR1/$tfile | awk '$1 == 1 {print $2}'`
	dd if=/dev/zero of=$DIR1/$tfile bs=1024k count=2

	$LCTL <<-EOF
		newdev
		attach echo_client ECHO_osc1 $ECHO_UUID
		setup $tOST
	EOF

	tECHOID=`$LCTL dl | grep $ECHO_UUID | awk '{ print $1 }'`
	$LCTL --device $tECHOID destroy "${tOBJID}:0"

    	$LCTL <<-EOF
		cfg_device ECHO_osc1
		cleanup
		detach
	EOF

	# reading of 1st stripe should pass
	dd if=$DIR2/$tfile of=/dev/null bs=1024k count=1 || error
	# reading of 2nd stripe should fail (this stripe was destroyed)
	dd if=$DIR2/$tfile of=/dev/null bs=1024k count=1 skip=1 && error

	# now, recreating test file
	dd if=/dev/zero of=$DIR1/$tfile bs=1024k count=2 || error
	# reading of 1st stripe should pass
	dd if=$DIR2/$tfile of=/dev/null bs=1024k count=1 || error
	# reading of 2nd stripe should pass
	dd if=$DIR2/$tfile of=/dev/null bs=1024k count=1 skip=1 || error
}
run_test 28 "read/write/truncate file with lost stripes"

test_29() { # bug 10999
	touch $DIR1/$tfile
	#define OBD_FAIL_LDLM_GLIMPSE  0x30f
	lctl set_param fail_loc=0x8000030f
	ls -l $DIR2/$tfile &
	usleep 500
	dd if=/dev/zero of=$DIR1/$tfile bs=4k count=1
	wait
}
#bug 11549 - permanently turn test off in b1_5
run_test 29 "lock put race between glimpse and enqueue ========="

test_30() { #bug #11110, LU-2523
	test_mkdir -p $DIR1/$tdir
	cp -f /bin/bash $DIR1/$tdir/bash
	/bin/sh -c 'sleep 1; rm -f $DIR2/$tdir/bash;
		    cp /bin/bash $DIR2/$tdir' &
	$DIR1/$tdir/bash -c 'sleep 2;
		openfile -f O_RDONLY /proc/$$/exe >& /dev/null; echo $?'
	wait
	true
}

run_test 30 "recreate file race"

test_31a() {
	test_mkdir -p $DIR1/$tdir || error "Creating dir $DIR1/$tdir"
	local writes=$(LANG=C dd if=/dev/zero of=$DIR/$tdir/$tfile \
		       count=1 2>&1 | awk 'BEGIN { FS="+" } /out/ {print $1}')
	#define OBD_FAIL_LDLM_CANCEL_BL_CB_RACE   0x314
	lctl set_param fail_loc=0x314
	local reads=$(LANG=C dd if=$DIR2/$tdir/$tfile of=/dev/null 2>&1 |
		      awk 'BEGIN { FS="+" } /in/ {print $1}')
	[ $reads -eq $writes ] || error "read" $reads "blocks, must be" $writes
}
run_test 31a "voluntary cancel / blocking ast race=============="

test_31b() {
	remote_ost || { skip "local OST" && return 0; }
	remote_ost_nodsh && skip "remote OST w/o dsh" && return 0

	# make sure there is no local locks due to destroy
	wait_mds_ost_sync || error "wait_mds_ost_sync()"
	wait_delete_completed || error "wait_delete_completed()"

	test_mkdir -p $DIR1/$tdir || error "Creating dir $DIR1/$tdir"
        lfs setstripe $DIR/$tdir/$tfile -i 0 -c 1
        cp /etc/hosts $DIR/$tdir/$tfile
        #define OBD_FAIL_LDLM_CANCEL_BL_CB_RACE   0x314
        lctl set_param fail_loc=0x314
        #define OBD_FAIL_LDLM_OST_FAIL_RACE      0x316
        do_facet ost1 lctl set_param fail_loc=0x316
        # Don't crash kernel
        cat $DIR2/$tdir/$tfile > /dev/null 2>&1
        lctl set_param fail_loc=0
        do_facet ost1 lctl set_param fail_loc=0
        # cleanup: reconnect the client back
        df $DIR2
}
run_test 31b "voluntary OST cancel / blocking ast race=============="

# enable/disable lockless truncate feature, depending on the arg 0/1
enable_lockless_truncate() {
        lctl set_param -n osc.*.lockless_truncate $1
}

test_32a() { # bug 11270
	local p="$TMP/$TESTSUITE-$TESTNAME.parameters"
	save_lustre_params client "osc.*.lockless_truncate" > $p
        cancel_lru_locks osc
        enable_lockless_truncate 1
        rm -f $DIR1/$tfile
        lfs setstripe -c -1 $DIR1/$tfile
        dd if=/dev/zero of=$DIR1/$tfile count=$OSTCOUNT bs=$STRIPE_BYTES > \
                /dev/null 2>&1
        clear_osc_stats

        log "checking cached lockless truncate"
        $TRUNCATE $DIR1/$tfile 8000000
        $CHECKSTAT -s 8000000 $DIR2/$tfile || error "wrong file size"
	[ $(calc_osc_stats lockless_truncate) -ne 0 ] ||
		error "cached truncate isn't lockless"

        log "checking not cached lockless truncate"
        $TRUNCATE $DIR2/$tfile 5000000
        $CHECKSTAT -s 5000000 $DIR1/$tfile || error "wrong file size"
	[ $(calc_osc_stats lockless_truncate) -ne 0 ] ||
		error "not cached truncate isn't lockless"

        log "disabled lockless truncate"
        enable_lockless_truncate 0
        clear_osc_stats
        $TRUNCATE $DIR2/$tfile 3000000
        $CHECKSTAT -s 3000000 $DIR1/$tfile || error "wrong file size"
        [ $(calc_osc_stats lockless_truncate) -eq 0 ] ||
                error "lockless truncate disabling failed"
        rm $DIR1/$tfile
        # restore lockless_truncate default values
        restore_lustre_params < $p
        rm -f $p
}
run_test 32a "lockless truncate"

test_32b() { # bug 11270
        remote_ost_nodsh && skip "remote OST with nodsh" && return

	local node
	local facets=$(get_facets OST)
	local p="$TMP/$TESTSUITE-$TESTNAME.parameters"

	save_lustre_params client "osc.*.contention_seconds" > $p
	save_lustre_params $facets \
		"ldlm.namespaces.filter-*.max_nolock_bytes" >> $p
	save_lustre_params $facets \
		"ldlm.namespaces.filter-*.contended_locks" >> $p
	save_lustre_params $facets \
		"ldlm.namespaces.filter-*.contention_seconds" >> $p
	clear_osc_stats

        # agressive lockless i/o settings
        for node in $(osts_nodes); do
                do_node $node 'lctl set_param -n ldlm.namespaces.filter-*.max_nolock_bytes 2000000; lctl set_param -n ldlm.namespaces.filter-*.contended_locks 0; lctl set_param -n ldlm.namespaces.filter-*.contention_seconds 60'
        done
        lctl set_param -n osc.*.contention_seconds 60
        for i in $(seq 5); do
                dd if=/dev/zero of=$DIR1/$tfile bs=4k count=1 conv=notrunc > /dev/null 2>&1
                dd if=/dev/zero of=$DIR2/$tfile bs=4k count=1 conv=notrunc > /dev/null 2>&1
        done
        [ $(calc_osc_stats lockless_write_bytes) -ne 0 ] || error "lockless i/o was not triggered"
        # disable lockless i/o (it is disabled by default)
        for node in $(osts_nodes); do
                do_node $node 'lctl set_param -n ldlm.namespaces.filter-*.max_nolock_bytes 0; lctl set_param -n ldlm.namespaces.filter-*.contended_locks 32; lctl set_param -n ldlm.namespaces.filter-*.contention_seconds 0'
        done
        # set contention_seconds to 0 at client too, otherwise Lustre still
        # remembers lock contention
        lctl set_param -n osc.*.contention_seconds 0
        clear_osc_stats
        for i in $(seq 1); do
                dd if=/dev/zero of=$DIR1/$tfile bs=4k count=1 conv=notrunc > /dev/null 2>&1
                dd if=/dev/zero of=$DIR2/$tfile bs=4k count=1 conv=notrunc > /dev/null 2>&1
        done
        [ $(calc_osc_stats lockless_write_bytes) -eq 0 ] ||
                error "lockless i/o works when disabled"
        rm -f $DIR1/$tfile
        restore_lustre_params <$p
        rm -f $p
}
run_test 32b "lockless i/o"

print_jbd_stat () {
    local dev
    local mdts=$(get_facets MDS)
    local varcvs
    local mds

    local stat=0
    for mds in ${mdts//,/ }; do
        varsvc=${mds}_svc
        dev=$(basename $(do_facet $mds "lctl get_param -n osd*.${!varsvc}.mntdev|\
		xargs readlink -f" ))
	val=$(do_facet $mds "cat /proc/fs/jbd*/${dev}{,:*,-*}/info 2>/dev/null |
		head -n1")
        val=${val%% *};
        stat=$(( stat + val))
    done
    echo $stat
}

# commit on sharing tests
test_33a() {
    remote_mds_nodsh && skip "remote MDS with nodsh" && return

    [ -z "$CLIENTS" ] && skip "Need two or more clients, have $CLIENTS" && return 0
    [ $CLIENTCOUNT -lt 2 ] &&
	skip "Need two or more clients, have $CLIENTCOUNT" && return 0

    local nfiles=${TEST33_NFILES:-10000}
    local param_file=$TMP/$tfile-params
    local fstype=$(facet_fstype $SINGLEMDS)

	save_lustre_params $(get_facets MDS) \
		"mdt.*.commit_on_sharing" > $param_file

    local COS
    local jbdold="N/A"
    local jbdnew="N/A"
    local jbd

    for COS in 0 1; do
        do_facet $SINGLEMDS lctl set_param mdt.*.commit_on_sharing=$COS
        avgjbd=0
        avgtime=0
        for i in 1 2 3; do
            do_nodes $CLIENT1,$CLIENT2 "mkdir -p $DIR1/$tdir-\\\$(hostname)-$i"

            [ $fstype = ldiskfs ] && jbdold=$(print_jbd_stat)
            echo "=== START createmany old: $jbdold transaction"
            local elapsed=$(do_and_time "do_nodes $CLIENT1,$CLIENT2 createmany -o $DIR1/$tdir-\\\$(hostname)-$i/f- -r $DIR2/$tdir-\\\$(hostname)-$i/f- $nfiles > /dev/null 2>&1")
            [ $fstype = ldiskfs ] && jbdnew=$(print_jbd_stat)
            [ $fstype = ldiskfs ] && jbd=$(( jbdnew - jbdold ))
            echo "=== END   createmany new: $jbdnew transaction :  $jbd transactions  nfiles $nfiles time $elapsed COS=$COS"
            [ $fstype = ldiskfs ] && avgjbd=$(( avgjbd + jbd ))
            avgtime=$(( avgtime + elapsed ))
        done
        eval cos${COS}_jbd=$((avgjbd / 3))
        eval cos${COS}_time=$((avgtime / 3))
    done

    echo "COS=0 transactions (avg): $cos0_jbd  time (avg): $cos0_time"
    echo "COS=1 transactions (avg): $cos1_jbd  time (avg): $cos1_time"
    [ "$cos0_jbd" != 0 ] && echo "COS=1 vs COS=0 jbd:  $((((cos1_jbd/cos0_jbd - 1)) * 100 )) %"
    [ "$cos0_time" != 0 ] && echo "COS=1 vs COS=0 time: $((((cos1_time/cos0_time - 1)) * 100 )) %"

    restore_lustre_params < $param_file
    rm -f $param_file
    return 0
}
run_test 33a "commit on sharing, cross crete/delete, 2 clients, benchmark"

# commit on sharing tests
test_33b() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return

	[ -n "$CLIENTS" ] || { skip "Need two or more clients" && return 0; }
	[ $CLIENTCOUNT -ge 2 ] ||
		{ skip "Need two or more clients, have $CLIENTCOUNT" &&
								return 0; }
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	local nfiles=${TEST33_NFILES:-10000}
	local param_file=$TMP/$tfile-params

	save_lustre_params $(get_facets MDS) \
		"mdt.*.commit_on_sharing" > $param_file

	local COS
	local jbdold
	local jbdnew
	local jbd
	local MDTIDX=1

	for COS in 0 1; do
		do_facet $SINGLEMDS lctl set_param mdt.*.commit_on_sharing=$COS
		avgjbd=0
		avgtime=0
		for i in 1 2 3; do
			do_node $CLIENT1 "$LFS mkdir -i $MDTIDX -p \
					  $DIR1/$tdir-\\\$(hostname)-$i"

			jbdold=$(print_jbd_stat)
			echo "=== START createmany old: $jbdold transaction"
			local elapsed=$(do_and_time "do_nodes $CLIENT1,$CLIENT2\
				createmany -o $DIR1/$tdir-\\\$(hostname)-$i/f- \
				-r $DIR2/$tdir-\\\$(hostname)-$i/f- $nfiles > \
								/dev/null 2>&1")
			jbdnew=$(print_jbd_stat)
			jbd=$(( jbdnew - jbdold ))
			echo "=== END   createmany new: $jbdnew transaction : \
			$jbd transactions nfiles $nfiles time $elapsed COS=$COS"
			avgjbd=$(( avgjbd + jbd ))
			avgtime=$(( avgtime + elapsed ))
		done
		eval cos${COS}_jbd=$((avgjbd / 3))
		eval cos${COS}_time=$((avgtime / 3))
	done

	echo "COS=0 transactions (avg): $cos0_jbd  time (avg): $cos0_time"
	echo "COS=1 transactions (avg): $cos1_jbd  time (avg): $cos1_time"
	[ "$cos0_jbd" != 0 ] &&
	    echo "COS=1 vs COS=0 jbd: $(((cos1_jbd/cos0_jbd - 1) * 100)) %"
	[ "$cos0_time" != 0 ] &&
	    echo "COS=1 vs COS=0 time: $(((cos1_time/cos0_time - 1) * 100)) %"

	restore_lustre_params < $param_file
	rm -f $param_file
	return 0
}
run_test 33b "COS: cross create/delete, 2 clients, benchmark under remote dir"

# End commit on sharing tests

get_ost_lock_timeouts() {
    local nodes=${1:-$(comma_list $(osts_nodes))}

    local locks=$(do_nodes $nodes \
        "lctl get_param -n ldlm.namespaces.filter-*.lock_timeouts" | calc_sum)

    echo $locks
}

cleanup_34() {
	local i
	trap 0
	do_nodes $(comma_list $(osts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	for i in $(seq $OSTCOUNT); do
		wait_osc_import_state client ost$i FULL
	done
}

test_34() { #16129
        local OPER
        local lock_in
        local lock_out
	trap cleanup_34 EXIT RETURN
        for OPER in notimeout timeout ; do
                rm $DIR1/$tfile 2>/dev/null
                lock_in=$(get_ost_lock_timeouts)
                if [ $OPER == "timeout" ] ; then
                        for j in `seq $OSTCOUNT`; do
                                #define OBD_FAIL_PTLRPC_HPREQ_TIMEOUT    0x511
                                do_facet ost$j lctl set_param fail_loc=0x511
                        done
                        echo lock should expire
                else
                        for j in `seq $OSTCOUNT`; do
                                #define OBD_FAIL_PTLRPC_HPREQ_NOTIMEOUT  0x512
                                do_facet ost$j lctl set_param fail_loc=0x512
                        done
                        echo lock should not expire
                fi
                echo writing on client1
                dd if=/dev/zero of=$DIR1/$tfile count=100 conv=notrunc > /dev/null 2>&1
                sync &
                echo reading on client2
                dd of=/dev/null if=$DIR2/$tfile > /dev/null 2>&1
                # wait for a lock timeout
                sleep 4
                lock_out=$(get_ost_lock_timeouts)
                if [ $OPER == "timeout" ] ; then
                        if [ $lock_in == $lock_out ]; then
                                error "no lock timeout happened"
                        else
                                echo "success"
                        fi
                else
                        if [ $lock_in != $lock_out ]; then
                                error "lock timeout happened"
                        else
                                echo "success"
                        fi
                fi
        done
	cleanup_34
}
run_test 34 "no lock timeout under IO"

test_35() { # bug 17645
        local generation=[]
        local count=0
	gen=$(lctl get_param mdc.$FSNAME-MDT*-mdc-*.import | grep generation |
		awk '/generation/{print $2}')
	for g in $gen; do
            generation[count]=$g
            let count=count+1
        done

	test_mkdir -p $MOUNT1/$tfile
        cancel_lru_locks mdc

        # Let's initiate -EINTR situation by setting fail_loc and take
        # write lock on same file from same client. This will not cause
        # bl_ast yet as lock is already in local cache.
#define OBD_FAIL_LDLM_INTR_CP_AST        0x317
        do_facet client "lctl set_param fail_loc=0x80000317"
        local timeout=`do_facet $SINGLEMDS lctl get_param  -n timeout`
        let timeout=timeout*3
        local nr=0
        while test $nr -lt 10; do
                log "Race attempt $nr"
                local blk1=`lctl get_param -n ldlm.services.ldlm_cbd.stats | awk '/ldlm_bl_callback/ {print $2}'`
                test "x$blk1" = "x" && blk1=0
                createmany -o $MOUNT2/$tfile/a 4000 &
                pid1=$!
                sleep 1

                # Let's make conflict and bl_ast
                ls -la $MOUNT1/$tfile > /dev/null &
                pid2=$!

                log "Wait for $pid1 $pid2 for $timeout sec..."
                sleep $timeout
                kill -9 $pid1 $pid2 > /dev/null 2>&1
                wait
                local blk2=`lctl get_param -n ldlm.services.ldlm_cbd.stats | awk '/ldlm_bl_callback/ {print $2}'`
                test "x$blk2" = "x" && blk2=0
                test $blk2 -gt $blk1 && break
                rm -fr $MOUNT1/$tfile/*
                cancel_lru_locks mdc
                let nr=nr+1
        done
        do_facet client "lctl set_param fail_loc=0x0"
        df -h $MOUNT1 $MOUNT2
        count=0
	gen=$(lctl get_param mdc.$FSNAME-MDT*-mdc-*.import | grep generation |
		awk '/generation/{print $2}')
	for g in $gen; do
	    if ! test "$g" -eq "${generation[count]}"; then
		list=$(lctl list_param mdc.$FSNAME-MDT*-mdc-*.import)
		local c = 0
		for imp in $list; do
			if [ $c = $count ]; then
				break
			fi
			c=c+1
		done
		imp=$(echo "$imp" | awk -F"." '{print $2}')
		error "Eviction happened on import $imp"
            fi
            let count=count+1
        done
}
run_test 35 "-EINTR cp_ast vs. bl_ast race does not evict client"

test_36() { #bug 16417
	local SIZE
	local SIZE_B
	local i

	test_mkdir -p $DIR1/$tdir
	$LFS setstripe -c -1 $DIR1/$tdir
	i=0
	SIZE=50
	let SIZE_B=SIZE*1024*1024
	sync; sleep 5; sync # wait for delete thread

	while [ $i -le 10 ]; do
		lctl mark "start test"
		local before=$(lfs_df $MOUNT1 | awk '/^filesystem/{ print $4; exit }')
		dd if=/dev/zero of=$DIR1/$tdir/$tfile bs=1M count=$SIZE ||
			error "dd $DIR1/$tdir/$tfile ${SIZE}MB failed"
		sync          # sync data from client cache
		sync_all_data # sync data from server cache (delayed allocation)
		sleep 2
		local after_dd=$(lfs_df $MOUNT1 | awk '/^filesystem/{ print $4; exit }')
		multiop_bg_pause $DIR2/$tdir/$tfile O_r${SIZE_B}c || return 3
		read_pid=$!
		rm -f $DIR1/$tdir/$tfile
		kill -USR1 $read_pid
		wait $read_pid
		wait_delete_completed
		local after=$(lfs_df $MOUNT1 | awk '/^filesystem/{ print $4; exit }')
		echo "*** cycle($i) *** before($before) after_dd($after_dd)" \
			"after($after)"
		# this free space! not used
		(( $after_dd <= $after)) ||
			error "space leaked after_dd:$after_dd > after:$after"
		let i=i+1
	done
}
run_test 36 "handle ESTALE/open-unlink correctly"

test_37() { # bug 18695
	test_mkdir -p $DIR1/$tdir
	multiop_bg_pause $DIR1/$tdir D_c || return 1
	MULTIPID=$!
	# create large directory (32kB seems enough from e2fsck, ~= 1000 files)
	createmany -m $DIR2/$tdir/f 10000
	# set mtime/atime backward
	touch -t 198001010000 $DIR2/$tdir
	kill -USR1 $MULTIPID
	nr_files=`lfs find $DIR1/$tdir -type f | wc -l`
	[ $nr_files -eq 10000 ] || error "$nr_files != 10000 truncated directory?"

}
run_test 37 "check i_size is not updated for directory on close (bug 18695) =============="

# this should be set to past
TEST_39_MTIME=`date -d "1 year ago" +%s`

# bug 11063
test_39a() {
	local client1=${CLIENT1:-`hostname`}
	local client2=${CLIENT2:-`hostname`}

	do_node $client1 "touch $DIR1/$tfile"

	do_node $client1 "touch -m -d @$TEST_39_MTIME $DIR1/$tfile"
	local mtime1=`do_node $client2 "stat -c %Y $DIR1/$tfile"`
	[ "$mtime1" = $TEST_39_MTIME ] || \
		error "mtime is not set to past: $mtime1, should be $TEST_39_MTIME"

	local d1=`do_node $client1 date +%s`
	do_node $client1 'echo hello >> '$DIR1/$tfile
	local d2=`do_node $client1 date +%s`

	local mtime2=`do_node $client2 "stat -c %Y $DIR1/$tfile"`
	[ "$mtime2" -ge "$d1" ] && [ "$mtime2" -le "$d2" ] || \
		error "mtime is not updated on write: $d1 <= $mtime2 <= $d2"

	do_node $client1 "mv $DIR1/$tfile $DIR1/$tfile-1"

	for (( i=0; i < 2; i++ )) ; do
		local mtime3=`do_node $client2 "stat -c %Y $DIR1/$tfile-1"`
		[ "$mtime2" = "$mtime3" ] || \
			error "mtime ($mtime2) changed (to $mtime3) on rename"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39a "test from 11063 =================================="

test_39b() {
	local client1=${CLIENT1:-`hostname`}
	local client2=${CLIENT2:-`hostname`}

	touch $DIR1/$tfile

	local mtime1=`stat -c %Y $DIR1/$tfile`
	local mtime2=`do_node $client2 "stat -c %Y $DIR1/$tfile"`

	sleep 1
	touch -m -d @$TEST_39_MTIME $DIR1/$tfile

	for (( i=0; i < 2; i++ )) ; do
		local mtime3=`stat -c %Y $DIR1/$tfile`
		local mtime4=`do_node $client2 "stat -c %Y $DIR1/$tfile"`

		[ "$mtime3" = "$mtime4" ] || \
			error "different mtime on clients: $mtime3, $mtime4"
		[ "$mtime3" = $TEST_39_MTIME ] || \
			error "lost mtime: $mtime3, should be $TEST_39_MTIME"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39b "11063 problem 1 =================================="

test_39c() {
	local client1=${CLIENT1:-`hostname`}
	local client2=${CLIENT2:-`hostname`}

	echo hello > $DIR1/$tfile

	local mtime1=`stat -c %Y $DIR1/$tfile`
	local mtime2=`do_node $client2 "stat -c %Y $DIR1/$tfile"`
	[ "$mtime1" = "$mtime2" ] || \
		error "create: different mtime on clients: $mtime1, $mtime2"

	sleep 1
	$TRUNCATE $DIR1/$tfile 1

	for (( i=0; i < 2; i++ )) ; do
		local mtime3=`stat -c %Y $DIR1/$tfile`
		local mtime4=`do_node $client2 "stat -c %Y $DIR1/$tfile"`

		[ "$mtime3" = "$mtime4" ] || \
			error "different mtime on clients: $mtime3, $mtime4"
		[ "$mtime3" -gt $mtime2 ] || \
			error "truncate did not update mtime: $mtime2, $mtime3"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39c "check truncate mtime update ======================"

# check that pid exists hence second operation wasn't blocked by first one
# if it is so then there is no conflict, return 0
# else second operation is conflicting with first one, return 1
check_pdo_conflict() {
	local pid=$1
	local conflict=0
	sleep 1 # to ensure OP1 is finished on client if OP2 is blocked by OP1
	if [[ `ps --pid $pid | wc -l` == 1 ]]; then
		conflict=1
		echo "Conflict"
	else
		echo "No conflict"
	fi
	return $conflict
}

# pdirop tests
# test 40: check non-blocking operations
test_40a() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mkdir $DIR1/$tfile &
	PID1=$!
	sleep 1
	touch $DIR2/$tfile-2
	check_pdo_conflict $PID1 || error "create is blocked"
	mkdir $DIR2/$tfile-3
	check_pdo_conflict $PID1 || error "mkdir is blocked"
	link $DIR2/$tfile-2 $DIR2/$tfile-4
	check_pdo_conflict $PID1 || error "link is blocked"
	mv $DIR2/$tfile-2 $DIR2/$tfile-5
	check_pdo_conflict $PID1 || error "rename is blocked"
	stat $DIR2/$tfile-3 $DIR2/$tfile-4 > /dev/null
	check_pdo_conflict $PID1 || error "getattr is blocked"
	rm $DIR2/$tfile-4 $DIR2/$tfile-5
	rmdir $DIR2/$tfile-3
	check_pdo_conflict $PID1 || error "unlink is blocked"

	# all operations above shouldn't wait the first one
	check_pdo_conflict $PID1 || error "parallel operation is blocked"
	wait $PID1
	rm -r $DIR1/*
	return 0
}
run_test 40a "pdirops: create vs others =============="

test_40b() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	touch $DIR1/$tfile &
	PID1=$!
	sleep 1
	# open|create
	touch $DIR2/$tfile-2
	check_pdo_conflict $PID1 || error "create is blocked"
	mkdir $DIR2/$tfile-3
	check_pdo_conflict $PID1 || error "mkdir is blocked"
	link $DIR2/$tfile-2 $DIR2/$tfile-4
	check_pdo_conflict $PID1 || error "link is blocked"
	mv $DIR2/$tfile-2 $DIR2/$tfile-5
	check_pdo_conflict $PID1 || error "rename is blocked"
	stat $DIR2/$tfile-3 $DIR2/$tfile-4 > /dev/null
	check_pdo_conflict $PID1 || error "getattr is blocked"
	rm $DIR2/$tfile-4 $DIR2/$tfile-5
	rmdir $DIR2/$tfile-3
	check_pdo_conflict $PID1 || error "unlink is blocked"
	# all operations above shouldn't wait the first one

        check_pdo_conflict $PID1 || error "parallel operation is blocked"
	wait $PID1
	rm -r $DIR1/*
	return 0
}
run_test 40b "pdirops: open|create and others =============="

test_40c() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	link $DIR1/$tfile $DIR1/$tfile-0 &
	PID1=$!
	sleep 1
	# open|create
	touch $DIR2/$tfile-2
	check_pdo_conflict $PID1 || error "create is blocked"
	mkdir $DIR2/$tfile-3
	check_pdo_conflict $PID1 || error "mkdir is blocked"
	link $DIR2/$tfile-2 $DIR2/$tfile-4
	check_pdo_conflict $PID1 || error "link is blocked"
	mv $DIR2/$tfile-2 $DIR2/$tfile-5
	check_pdo_conflict $PID1 || error "rename is blocked"
	stat $DIR2/$tfile-3 $DIR2/$tfile-4 > /dev/null
	check_pdo_conflict $PID1 || error "getattr is blocked"
	rm $DIR2/$tfile-4 $DIR2/$tfile-5
	rmdir $DIR2/$tfile-3
	check_pdo_conflict $PID1 || error "unlink is blocked"

        # all operations above shouldn't wait the first one
	check_pdo_conflict $PID1 || error "parallel operation is blocked"
	wait $PID1
	rm -r $DIR1/*
	return 0
}
run_test 40c "pdirops: link and others =============="

test_40d() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	rm $DIR1/$tfile &
	PID1=$!
	sleep 1
	# open|create
	touch $DIR2/$tfile-2
	check_pdo_conflict $PID1 || error "create is blocked"
	mkdir $DIR2/$tfile-3
	check_pdo_conflict $PID1 || error "mkdir is blocked"
	link $DIR2/$tfile-2 $DIR2/$tfile-4
	check_pdo_conflict $PID1 || error "link is blocked"
	mv $DIR2/$tfile-2 $DIR2/$tfile-5
	check_pdo_conflict $PID1 || error "rename is blocked"
	stat $DIR2/$tfile-3 $DIR2/$tfile-4 > /dev/null
	check_pdo_conflict $PID1 || error "getattr is blocked"
	rm $DIR2/$tfile-4 $DIR2/$tfile-5
	rmdir $DIR2/$tfile-3
	check_pdo_conflict $PID1 || error "unlink is blocked"

	# all operations above shouldn't wait the first one
	check_pdo_conflict $PID1 || error "parallel operation is blocked"
	wait $PID1
	return 0
}
run_test 40d "pdirops: unlink and others =============="

test_40e() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mv $DIR1/$tfile $DIR1/$tfile-0 &
	PID1=$!
	sleep 1
	# open|create
	touch $DIR2/$tfile-2
	check_pdo_conflict $PID1 || error "create is blocked"
	mkdir $DIR2/$tfile-3
	check_pdo_conflict $PID1 || error "mkdir is blocked"
	link $DIR2/$tfile-2 $DIR2/$tfile-4
	check_pdo_conflict $PID1 || error "link is blocked"
	stat $DIR2/$tfile-3 $DIR2/$tfile-4 > /dev/null
	check_pdo_conflict $PID1 || error "getattr is blocked"
	rm $DIR2/$tfile-4 $DIR2/$tfile-2
	rmdir $DIR2/$tfile-3
	check_pdo_conflict $PID1 || error "unlink is blocked"

       # all operations above shouldn't wait the first one
	check_pdo_conflict $PID1 || error "parallel operation is blocked"
	wait $PID1
	rm -r $DIR1/*
	return 0
}
run_test 40e "pdirops: rename and others =============="

# test 41: create blocking operations
test_41a() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$!
	sleep 1
	mkdir $DIR2/$tfile && error "mkdir must fail"
	check_pdo_conflict $PID1 && { wait $PID1; echo "mkdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 41a "pdirops: create vs mkdir =============="

test_41b() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$!
	sleep 1
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c && error "create must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 41b "pdirops: create vs create =============="

test_41c() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$!
	sleep 1
	link $DIR2/$tfile-2 $DIR2/$tfile && error "link must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 41c "pdirops: create vs link =============="

test_41d() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$!
	sleep 1
	rm $DIR2/$tfile || error "unlink must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 41d "pdirops: create vs unlink =============="

test_41e() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile-2 $DIR2/$tfile || error "rename must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 41e "pdirops: create and rename (tgt) =============="

test_41f() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile $DIR2/$tfile-2 || error "rename must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 41f "pdirops: create and rename (src) =============="

test_41g() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$!
	sleep 1
	stat $DIR2/$tfile > /dev/null || error "stat must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 41g "pdirops: create vs getattr =============="

test_41h() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$!
	sleep 1
	ls -lia $DIR2/ > /dev/null
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 41h "pdirops: create vs readdir =============="

# test 42: unlink and blocking operations
test_42a() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mkdir $DIR1/$tfile &
	PID1=$!
	sleep 1
	mkdir $DIR2/$tfile && error "mkdir must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "mkdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 42a "pdirops: mkdir vs mkdir =============="

test_42b() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mkdir $DIR1/$tfile &
	PID1=$!
	sleep 1
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c && error "create must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 42b "pdirops: mkdir vs create =============="

test_42c() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mkdir $DIR1/$tfile &
	PID1=$!
	sleep 1
	link $DIR2/$tfile-2 $DIR2/$tfile && error "link must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 42c "pdirops: mkdir vs link =============="

test_42d() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mkdir $DIR1/$tfile &
	PID1=$!
	sleep 1
	rmdir $DIR2/$tfile || error "unlink must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 42d "pdirops: mkdir vs unlink =============="

test_42e() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mkdir $DIR1/$tfile &
	PID1=$!
	sleep 1
	mv -T $DIR2/$tfile-2 $DIR2/$tfile && error "rename must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 42e "pdirops: mkdir and rename (tgt) =============="

test_42f() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mkdir $DIR1/$tfile &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile $DIR2/$tfile-2 || error "rename must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 42f "pdirops: mkdir and rename (src) =============="

test_42g() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mkdir $DIR1/$tfile &
	PID1=$!
	sleep 1
	stat $DIR2/$tfile > /dev/null || error "stat must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 42g "pdirops: mkdir vs getattr =============="

test_42h() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mkdir $DIR1/$tfile &
	PID1=$!
	sleep 1
	ls -lia $DIR2/ > /dev/null
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 42h "pdirops: mkdir vs readdir =============="

# test 43: unlink and blocking operations
test_43a() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	rm $DIR1/$tfile &
	PID1=$!
	sleep 1
	mkdir $DIR2/$tfile || error "mkdir must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "mkdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 43a "pdirops: unlink vs mkdir =============="

test_43b() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	rm $DIR1/$tfile &
	PID1=$!
	sleep 1
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c || error "create must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 43b "pdirops: unlink vs create =============="

test_43c() {
	touch $DIR1/$tfile
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	rm $DIR1/$tfile &
	PID1=$!
	sleep 1
	link $DIR2/$tfile-2 $DIR2/$tfile || error "link must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 43c "pdirops: unlink vs link =============="

test_43d() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	rm $DIR1/$tfile &
	PID1=$!
	sleep 1
	rm $DIR2/$tfile && error "unlink must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 43d "pdirops: unlink vs unlink =============="

test_43e() {
	touch $DIR1/$tfile
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	rm $DIR1/$tfile &
	PID1=$!
	sleep 1
	mv -u $DIR2/$tfile-2 $DIR2/$tfile || error "rename must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 43e "pdirops: unlink and rename (tgt) =============="

test_43f() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	rm $DIR1/$tfile &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile $DIR2/$tfile-2 && error "rename must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 43f "pdirops: unlink and rename (src) =============="

test_43g() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	rm $DIR1/$tfile &
	PID1=$!
	sleep 1
	stat $DIR2/$tfile > /dev/null && error "stat must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 43g "pdirops: unlink vs getattr =============="

test_43h() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	rm $DIR1/$tfile &
	PID1=$!
	sleep 1
	ls -lia $DIR2/ > /dev/null
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 43h "pdirops: unlink vs readdir =============="

test_43i() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	rm $DIR1/$tfile &
	PID1=$!
	sleep 1
	$LFS mkdir -i 1 $DIR2/$tfile || error "remote mkdir must succeed"
	check_pdo_conflict $PID1 &&
		{ wait $PID1; error "remote mkdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 43i "pdirops: unlink vs remote mkdir"

# test 44: rename tgt and blocking operations
test_44a() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2   0x146
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000146
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	mkdir $DIR2/$tfile && error "mkdir must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "mkdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 44a "pdirops: rename tgt vs mkdir =============="

test_44b() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000146
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c && error "create must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 44b "pdirops: rename tgt vs create =============="

test_44c() {
	touch $DIR1/$tfile-2
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000146
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	link $DIR2/$tfile-3 $DIR2/$tfile && error "link must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 44c "pdirops: rename tgt vs link =============="

test_44d() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000146
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	rm $DIR2/$tfile || error "unlink must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 44d "pdirops: rename tgt vs unlink =============="

test_44e() {
	touch $DIR1/$tfile
	touch $DIR1/$tfile-2
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000146
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile-3 $DIR2/$tfile || error "rename must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 44e "pdirops: rename tgt and rename (tgt) =============="

test_44f() {
	touch $DIR1/$tfile-2
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000146
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile $DIR2/$tfile-3 || error "rename must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 44f "pdirops: rename tgt and rename (src) =============="

test_44g() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000146
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	stat $DIR2/$tfile > /dev/null || error "stat must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 44g "pdirops: rename tgt vs getattr =============="

test_44h() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000146
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	ls -lia $DIR2/ > /dev/null
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 44h "pdirops: rename tgt vs readdir =============="

# test 44: rename tgt and blocking operations
test_44i() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2   0x146
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000146
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	$LFS mkdir -i 1 $DIR2/$tfile && error "remote mkdir must fail"
	check_pdo_conflict $PID1 && { wait $PID1;
				error "remote mkdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 44i "pdirops: rename tgt vs remote mkdir"

# test 45: rename src and blocking operations
test_45a() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$!
	sleep 1
	mkdir $DIR2/$tfile || error "mkdir must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "mkdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 45a "pdirops: rename src vs mkdir =============="

test_45b() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$!
	sleep 1
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c || error "create must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 45b "pdirops: rename src vs create =============="

test_45c() {
	touch $DIR1/$tfile
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$!
	sleep 1
	link $DIR2/$tfile-3 $DIR2/$tfile || error "link must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 45c "pdirops: rename src vs link =============="

test_45d() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$!
	sleep 1
	rm $DIR2/$tfile && error "unlink must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 45d "pdirops: rename src vs unlink =============="

test_45e() {
	touch $DIR1/$tfile
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile-3 $DIR2/$tfile || error "rename must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 45e "pdirops: rename src and rename (tgt) =============="

test_45f() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile $DIR2/$tfile-3 && error "rename must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 45f "pdirops: rename src and rename (src) =============="

test_45g() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$!
	sleep 1
	stat $DIR2/$tfile > /dev/null && error "stat must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 45g "pdirops: rename src vs getattr =============="

test_45h() {
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$!
	sleep 1
	ls -lia $DIR2/ > /dev/null
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 45h "pdirops: unlink vs readdir =============="

test_45i() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$!
	sleep 1
	$LFS mkdir -i 1 $DIR2/$tfile || error "create remote dir must succeed"
	check_pdo_conflict $PID1 && { wait $PID1;
				error "create remote dir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 45i "pdirops: rename src vs remote mkdir"

# test 46: link and blocking operations
test_46a() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	mkdir $DIR2/$tfile && error "mkdir must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "mkdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 46a "pdirops: link vs mkdir =============="

test_46b() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c && error "create must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 46b "pdirops: link vs create =============="

test_46c() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	link $DIR2/$tfile $DIR2/$tfile && error "link must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 46c "pdirops: link vs link =============="

test_46d() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	rm $DIR2/$tfile || error "unlink must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 46d "pdirops: link vs unlink =============="

test_46e() {
	touch $DIR1/$tfile-2
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile-3 $DIR2/$tfile || error "rename must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 46e "pdirops: link and rename (tgt) =============="

test_46f() {
	touch $DIR1/$tfile-2
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile $DIR2/$tfile-3 || error "rename must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 46f "pdirops: link and rename (src) =============="

test_46g() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	stat $DIR2/$tfile > /dev/null || error "stat must succeed"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 46g "pdirops: link vs getattr =============="

test_46h() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	ls -lia $DIR2/ > /dev/null
	check_pdo_conflict $PID1 && { wait $PID1;
			error "readdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 46h "pdirops: link vs readdir =============="

test_46i() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$!
	sleep 1
	$LFS mkdir -i 1 $DIR2/$tfile && error "remote mkdir must fail"
	check_pdo_conflict $PID1 && { wait $PID1;
				error "remote mkdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 46i "pdirops: link vs remote mkdir"

# test 47: remote mkdir and blocking operations
test_47a() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$!
	sleep 1
	mkdir $DIR2/$tfile && error "mkdir must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "mkdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 47a "pdirops: remote mkdir vs mkdir"

test_47b() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$!
	sleep 1
	multiop $DIR2/$tfile oO_CREAT:O_EXCL:c && error "create must fail"
	check_pdo_conflict $PID1 && { wait $PID1;
					error "create isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 47b "pdirops: remote mkdir vs create"

test_47c() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$!
	sleep 1
	link $DIR2/$tfile-2 $DIR2/$tfile && error "link must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 47c "pdirops: remote mkdir vs link"

test_47d() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$!
	sleep 1
	rmdir $DIR2/$tfile || error "unlink must succeed"
	check_pdo_conflict $PID1 && { wait $PID1;
					error "unlink isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 47d "pdirops: remote mkdir vs unlink"

test_47e() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$!
	sleep 1
	mv -T $DIR2/$tfile-2 $DIR2/$tfile && error "rename must fail"
	check_pdo_conflict $PID1 && { wait $PID1;
					error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 47e "pdirops: remote mkdir and rename (tgt)"

test_47f() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$!
	sleep 1
	mv $DIR2/$tfile $DIR2/$tfile-2 || error "rename must succeed"
	check_pdo_conflict $PID1 && { wait $PID1;
					error "rename isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 47f "pdirops: remote mkdir and rename (src)"

test_47g() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$!
	sleep 1
	stat $DIR2/$tfile > /dev/null || error "stat must succeed"
	check_pdo_conflict $PID1 && { wait $PID1;
					error "getattr isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 47g "pdirops: remote mkdir vs getattr"

test_50() {
        trunc_size=4096
        dd if=/dev/zero of=$DIR1/$tfile bs=1K count=10
#define OBD_FAIL_OSC_CP_ENQ_RACE         0x410
        do_facet client "lctl set_param fail_loc=0x410"
        $TRUNCATE $DIR2/$tfile $trunc_size
        do_facet client "lctl set_param fail_loc=0x0"
        sleep 3
        size=`stat -c %s $DIR2/$tfile`
        [ $size -eq $trunc_size ] || error "wrong size"
}
run_test 50 "osc lvb attrs: enqueue vs. CP AST =============="

test_51a() {
	local filesize
	local origfile=/etc/hosts

	filesize=`stat -c %s $origfile`

	# create an empty file
	$MCREATE $DIR1/$tfile
	# cache layout lock on both mount point
	stat $DIR1/$tfile > /dev/null
	stat $DIR2/$tfile > /dev/null

	# open and sleep 2 seconds then read
	$MULTIOP $DIR2/$tfile o_2r${filesize}c &
	local pid=$!
	sleep 1

	# create the layout of testing file
	dd if=$origfile of=$DIR1/$tfile conv=notrunc > /dev/null

	# MULTIOP proc should be able to read enough bytes and exit
	sleep 2
	kill -0 $pid && error "multiop is still there"
	cmp $origfile $DIR2/$tfile || error "$MCREATE and $DIR2/$tfile differs"

	rm -f $DIR1/$tfile
}
run_test 51a "layout lock: refresh layout should work"

test_51b() {
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.3.59) ]] ||
		{ skip "Need MDS version at least 2.3.59"; return 0; }

	local tmpfile=`mktemp`

	# create an empty file
	$MCREATE $DIR1/$tfile

	# delay glimpse so that layout has changed when glimpse finish
#define OBD_FAIL_GLIMPSE_DELAY 0x1404
	$LCTL set_param fail_loc=0x1404
	stat -c %s $DIR2/$tfile |tee $tmpfile &
	local pid=$!
	sleep 1

	# create layout of testing file
	dd if=/dev/zero of=$DIR1/$tfile bs=1k count=1 conv=notrunc > /dev/null

	wait $pid
	local fsize=`cat $tmpfile`

	[ x$fsize = x1024 ] || error "file size is $fsize, should be 1024"

	rm -f $DIR1/$tfile $tmpfile
}
run_test 51b "layout lock: glimpse should be able to restart if layout changed"

test_51c() {
	[ $OSTCOUNT -ge 2 ] || { skip "need at least 2 osts"; return; }

	# set default layout to have 1 stripe
	mkdir -p $DIR1/$tdir
	$LFS setstripe -c 1 $DIR1/$tdir

	# create a file with empty layout
	$MCREATE $DIR1/$tdir/$tfile

#define OBD_FAIL_MDS_LL_BLOCK 0x172
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x172

	# change the layout of testing file
	echo "Setting layout to have $OSTCOUNT stripes ..."
	$LFS setstripe -c $OSTCOUNT $DIR1/$tdir/$tfile &
	pid=$!
	sleep 1

	# write something to the file, it should be blocked on fetching layout
	dd if=/dev/zero of=$DIR2/$tdir/$tfile bs=1k count=1 conv=notrunc
	local cnt=$($LFS getstripe -c $DIR2/$tdir/$tfile)
	[ $cnt -eq $OSTCOUNT ] || error "have $cnt stripes, expected $OSTCOUNT"

	rm -fr $DIR1/$tdir
}
run_test 51c "layout lock: IT_LAYOUT blocked and correct layout can be returned"

test_51d() {
	dd if=/dev/zero of=/$DIR1/$tfile bs=1M count=1
	cancel_lru_locks mdc

	# open should grant LAYOUT lock, mmap and read will install pages
	$MULTIOP $DIR1/$tfile oO_RDWR:SMR_Uc &
	local PID=$!
	sleep 1

	# rss before revoking
	local br=$(grep -A 10 $tfile /proc/$PID/smaps | awk '/^Rss/{print $2}')
	echo "Before revoking layout lock: $br KB mapped"

	# delete the file will revoke layout lock
	rm -f $DIR2/$tfile

	# rss after revoking
	local ar=$(grep -A 10 $tfile /proc/$PID/smaps | awk '/^Rss/{print $2}')

	kill -USR1 $PID
	wait $PID || error

	[ $ar -eq 0 ] || error "rss before: $br, after $ar, some pages remained"
}
run_test 51d "layout lock: losing layout lock should clean up memory map region"

test_54_part1()
{
	echo "==> rename vs getattr vs setxattr should not deadlock"
	mkdir -p $DIR/d1/d2/d3 || error "(1) mkdir failed"

	do_facet mds $LCTL set_param fail_loc=$1

	mv -T $DIR/d1/d2/d3 $DIR/d1/d3 &
	PID1=$!
	sleep 1

	stat $DIR/d1/d2 &
	PID2=$!
	sleep 1

	setfattr -n user.attr1 -v value1 $DIR2/d1 || error "(2) setfattr failed"
	wait $PID1 || error "(3) mv failed"
	wait $PID2 || error "(4) stat failed"
	echo

	rm -rf $DIR/d1
}

test_54_part2() {
	echo "==> rename vs getattr vs open vs getattr should not deadlock"
	mkdir -p $DIR/d1/d2/d3 || error "(1) mkdir failed"

	do_facet mds $LCTL set_param fail_loc=$1

	mv -T $DIR/d1/d2/d3 $DIR/d1/d3 &
	PID1=$!
	sleep 1

	stat $DIR/d1/d2 &
	PID2=$!
	sleep 1

	$MULTIOP $DIR2/d1/d2 Oc &
	PID3=$!
	sleep 1

	stat $DIR/d1 || error "(2) stat failed"

	wait $PID1 || error "(3) mv failed"
	wait $PID2 || error "(4) stat failed"
	wait $PID3 && error "(5) multiop failed"
	echo
	rm -rf $DIR/d1
}

test_54() {
	local p="$TMP/$TESTSUITE-$TESTNAME.parameters"
	save_lustre_params client "llite.*.xattr_cache" > $p
	lctl set_param llite.*.xattr_cache 1 ||
		{ skip "xattr cache is not supported"; return 0; }

#define OBD_FAIL_MDS_RENAME              0x153
#define OBD_FAIL_MDS_RENAME2             0x154
	test_54_part1 0x80000153 || error 10
	test_54_part1 0x80000154 || error 11
	test_54_part2 0x80000153 || error 12
	test_54_part2 0x80000154 || error 13

	restore_lustre_params < $p
	rm -f $p
}
run_test 54 "rename locking"

test_55a() {
	mkdir -p $DIR/d1/d2 $DIR/d3 || error "(1) mkdir failed"

#define OBD_FAIL_MDS_RENAME4              0x156
	do_facet mds $LCTL set_param fail_loc=0x80000156

	mv -T $DIR/d1/d2 $DIR/d3/d2 &
	PID1=$!
	sleep 1

	rm -r $DIR2/d3
	wait $PID1 && error "(2) mv succeeded"

	rm -rf $DIR/d1
}
run_test 55a "rename vs unlink target dir"

test_55b()
{
	mkdir -p $DIR/d1/d2 $DIR/d3 || error "(1) mkdir failed"

#define OBD_FAIL_MDS_RENAME4             0x156
	do_facet mds $LCTL set_param fail_loc=0x80000156

	mv -T $DIR/d1/d2 $DIR/d3/d2 &
	PID1=$!
	sleep 1

	rm -r $DIR2/d1
	wait $PID1 && error "(2) mv succeeded"

	rm -rf $DIR/d3
}
run_test 55b "rename vs unlink source dir"

test_55c()
{
	mkdir -p $DIR/d1/d2 $DIR/d3 || error "(1) mkdir failed"

#define OBD_FAIL_MDS_RENAME4              0x156
	do_facet mds $LCTL set_param fail_loc=0x156

	mv -T $DIR/d1/d2 $DIR/d3/d2 &
	PID1=$!
	sleep 1

	# while rename is sleeping, open and remove d3
	$MULTIOP $DIR2/d3 D_c &
	PID2=$!
	sleep 1
	rm -rf $DIR2/d3
	sleep 5

	# while rename is sleeping 2nd time, close d3
	kill -USR1 $PID2
	wait $PID2 || error "(3) multiop failed"

	wait $PID1 && error "(2) mv succeeded"

	rm -rf $DIR/d1
}
run_test 55c "rename vs unlink orphan target dir"

test_55d()
{
	touch $DIR/f1

#define OBD_FAIL_MDS_RENAME3              0x155
	do_facet mds $LCTL set_param fail_loc=0x155
	mv $DIR/f1 $DIR/$tdir &
	PID1=$!
	sleep 2

	# while rename is sleeping, create $tdir, but as a directory
	mkdir -p $DIR2/$tdir || error "(1) mkdir failed"

	# link in reverse locking order
	ln $DIR2/f1 $DIR2/$tdir/

	wait $PID1 && error "(2) mv succeeded"
	rm -rf $DIR/f1
}
run_test 55d "rename file vs link"

test_60() {
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.3.0) ]] ||
	{ skip "Need MDS version at least 2.3.0"; return; }
	# Create a file
	test_mkdir -p $DIR1/$tdir
	file1=$DIR1/$tdir/file
	file2=$DIR2/$tdir/file

	echo orig > $file2 || error "Could not create $file2"
	version=$($LFS data_version $file1)

	# Append data
	echo append >> $file2 || error "Could not append to $file2"
	version2=$($LFS data_version $file1)
	[ "$version" != "$version2" ] ||
	    error "append did not change data version: $version"

	# Overwrite data
	echo overwrite > $file2 || error "Could not overwrite $file2"
	version3=$($LFS data_version $file1)
	[ "$version2" != "$version3" ] ||
	    error "overwrite did not change data version: $version2"

	# Truncate before EOF
	$TRUNCATE $file2 3 || error "Could not truncate $file2"
	version4=$($LFS data_version $file1)
	[ "$version3" != "$version4" ] ||
	    error "truncate did not change data version: $version3"

	# Truncate after EOF
	$TRUNCATE $file2 123456 || error "Could not truncate $file2"
	version5=$($LFS data_version $file1)
	[ "$version4" != "$version5" ] ||
	    error "truncate did not change data version: $version4"

	# Chmod do not change version
	chmod 400 $file2 || error "Could not chmod 400 $file2"
	version6=$($LFS data_version $file1)
	[ "$version5" == "$version6" ] ||
	    error "chmod should not change data version: $version5 != $version6"

	# Chown do not change version
	chown $RUNAS_ID $file2 || error "Could not chown $RUNAS_ID $file2"
	version7=$($LFS data_version $file1)
	[ "$version5" == "$version7" ] ||
	    error "chown should not change data version: $version5 != $version7"
}
run_test 60 "Verify data_version behaviour"

test_70a() {
	local test_dir=$tdir/test_dir

	mkdir -p $DIR1/$tdir
	if [ $MDSCOUNT -ge 2 ]; then
		local MDTIDX=1
		$LFS mkdir -i $MDTIDX $DIR1/$test_dir ||
			error "Create remote directory failed"
	else
		mkdir -p $DIR1/$test_dir
	fi
	cd $DIR2/$test_dir || error "cd directory failed"
	rm -rf $DIR1/$test_dir || error "unlink directory failed"

	cd $DIR2/$tdir || error "exit directory"
}
run_test 70a "cd directory && rm directory"

test_70b() { # LU-2781
	local i
	mkdir -p $DIR1/$tdir

	touch $DIR1/$tdir/file
	for ((i = 0; i < 32; i++)); do
	    $LFS rm_entry $DIR1/$tdir/non_existent_dir &>/dev/null
	done
	rm $DIR1/$tdir/file || error "cannot remove file after rm_entry"

	touch $DIR1/$tdir/file
	$LFS mkdir -i0 $DIR1/$tdir/test_dir
	$LFS rm_entry $DIR1/$tdir/test_dir &>/dev/null
	rm -rf $DIR1/$tdir/test_dir ||
		error "cannot remove directory after rm_entry"
	rm $DIR1/$tdir/file || error "cannot remove file after rm_entry"
}
run_test 70b "remove files after calling rm_entry"

test_71() {
	local server_version=$(lustre_version_code $SINGLEMDS)

	[[ $server_version -lt $(version_code 2.1.6) ]] &&
		skip "Need MDS version at least 2.1.6" && return

	# Patch not applied to 2.2 and 2.3 branches
	[[ $server_version -ge $(version_code 2.2.0) ]] &&
	[[ $server_version -lt $(version_code 2.4.0) ]] &&
		skip "Need MDS version at least 2.4.0" && return

	checkfiemap --test ||
		{ skip "checkfiemap not runnable: $?" && return; }
	# write data this way: hole - data - hole - data
	dd if=/dev/urandom of=$DIR1/$tfile bs=40K seek=1 count=1
	[ "$(facet_fstype ost$(($($GETSTRIPE -i $DIR1/$tfile) + 1)))" = \
		"zfs" ] &&
		skip "ORI-366/LU-1941: FIEMAP unimplemented on ZFS" && return 0
	dd if=/dev/urandom of=$DIR1/$tfile bs=40K seek=3 count=1
	GET_STAT="lctl get_param -n ldlm.services.ldlm_cbd.stats"
	stat $DIR2/$tfile
	local can1=$($GET_STAT | awk '/ldlm_bl_callback/ {print $2}')
	echo $can1
	checkfiemap $DIR2/$tfile 81920 ||
		error "data is not flushed from client"
	local can2=$($GET_STAT | awk '/ldlm_bl_callback/ {print $2}')
	echo $can2

	# common case of "create file, copy file" on a single node
	# should not flush data from ost
	dd if=/dev/urandom of=$DIR1/$tfile bs=40K seek=1 count=1
	dd if=/dev/urandom of=$DIR1/$tfile bs=40K seek=3 count=1
	stat $DIR1/$tfile
	local can3=$($GET_STAT | awk '/ldlm_bl_callback/ {print $2}')
	echo $can3
	checkfiemap $DIR1/$tfile 81920 ||
	error 4
	local can4=$($GET_STAT | awk '/ldlm_bl_callback/ {print $2}')
	echo $can2
	[ $can3 -eq $can4 ] || error $((can2-can1)) "cancel RPC occured."
}
run_test 71 "correct file map just after write operation is finished"

test_72() {
	local p="$TMP/sanityN-$TESTNAME.parameters"
	local tlink1
	local tlink2
	save_lustre_params client "llite.*.xattr_cache" > $p
	lctl set_param llite.*.xattr_cache 1 ||
		{ skip "xattr cache is not supported"; return 0; }

	touch $DIR1/$tfile
	setfattr -n user.attr1 -v value1 $DIR1/$tfile ||
		error "setfattr1 failed"
	getfattr -n user.attr1 $DIR2/$tfile | grep value1 ||
		error "getfattr1 failed"
	setfattr -n user.attr1 -v value2 $DIR2/$tfile ||
		error "setfattr2 failed"
	getfattr -n user.attr1 $DIR1/$tfile | grep value2 ||
		error "getfattr2 failed"

	# check that trusted.link is consistent
	tlink1=$(getfattr -n trusted.link $DIR1/$tfile | md5sum)
	ln $DIR2/$tfile $DIR2/$tfile-2 || error "failed to link"
	tlink2=$(getfattr -n trusted.link $DIR1/$tfile | md5sum)
	echo "$tlink1 $tlink2"
	[ "$tlink1" = "$tlink2" ] && error "trusted.link should have changed!"

	rm -f $DIR2/$tfile

	restore_lustre_params < $p
	rm -f $p
}
run_test 72 "getxattr/setxattr cache should be consistent between nodes"

test_73() {
	local p="$TMP/sanityN-$TESTNAME.parameters"
	save_lustre_params client "llite.*.xattr_cache" > $p
	lctl set_param llite.*.xattr_cache 1 ||
		{ skip "xattr cache is not supported"; return 0; }

	touch $DIR1/$tfile
	setfattr -n user.attr1 -v value1 $DIR1/$tfile ||
		error "setfattr1 failed"
	getfattr -n user.attr1 $DIR2/$tfile || error "getfattr1 failed"
	getfattr -n user.attr1 $DIR1/$tfile || error "getfattr2 failed"
	clear_llite_stats
	# PR lock should be cached by now on both clients
	getfattr -n user.attr1 $DIR1/$tfile || error "getfattr3 failed"
	# 2 hits for getfattr(0)+getfattr(size)
	[ $(calc_llite_stats getxattr_hits) -eq 2 ] || error "not cached in $DIR1"
	getfattr -n user.attr1 $DIR2/$tfile || error "getfattr4 failed"
	# 4 hits for more getfattr(0)+getfattr(size)
	[ $(calc_llite_stats getxattr_hits) -eq 4 ] || error "not cached in $DIR2"
	rm -f $DIR2/$tfile

	restore_lustre_params < $p
	rm -f $p
}
run_test 73 "getxattr should not cause xattr lock cancellation"

test_74() {
	[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.4.93) ] &&
		skip "Need MDS version at least 2.4.93" && return

	dd if=/dev/zero of=$DIR1/$tfile-1 bs=1K count=1
	dd if=/dev/zero of=$DIR1/$tfile-2 bs=1K count=1
	flocks_test 4 $DIR1/$tfile-1 $DIR2/$tfile-2
}
run_test 74 "flock deadlock: different mounts =============="

# LU-3889
test_75() {
	$LFS setstripe -c 2 -S 1m -i 0 $DIR1/$tfile
	dd if=/dev/zero of=$DIR1/$tfile bs=1M count=2
	cancel_lru_locks osc

	dd of=$DIR1/$tfile if=/dev/zero bs=1M count=1 seek=1 conv=notrunc
	sync

	# define OBD_FAIL_LDLM_ENQUEUE_HANG 0x31d
	$LCTL set_param fail_loc=0x31d
	stat -c %s $DIR1/$tfile &
	local pid=$!
	sleep 1
	kill -9 $pid

	# For bad lock error handler we should ASSERT and got kernel panic here
	sleep 4
	$LCTL set_param fail_loc=0
}
run_test 75 "osc: upcall after unuse lock==================="

test_76() { #LU-946
	[[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.5.53) ]] &&
		skip "Need MDS version at least 2.5.53" && return

	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	local fcount=2048
	declare -a fd_list
	declare -a fid_list

	if remote_mds; then
		nid=$($LCTL list_nids | sed  "s/\./\\\./g")
	else
		nid="0@lo"
	fi

	rm -rf $DIR/$tdir
	test_mkdir -p $DIR/$tdir

	# drop all open locks and close any cached "open" files on the client
	cancel_lru_locks mdc

	echo -n "open files "
	ulimit -n 8096
	for ((i = 0; i < $fcount; i++)); do
		touch $DIR/$tdir/f_$i
		local fd=$(free_fd)
		local cmd="exec $fd<$DIR/$tdir/f_$i"
		eval $cmd
		fd_list[i]=$fd
		echo -n "."
	done
	echo

	local get_open_fids="$LCTL get_param -n mdt.*.exports.'$nid'.open_files"
	local fid_list=($(do_nodes $(comma_list $(mdts_nodes)) $get_open_fids))

	# Possible errors in openfiles FID list.
	# 1. Missing FIDs. Check 1
	# 2. Extra FIDs. Check 1
	# 3. Duplicated FID. Check 2
	# 4. Invalid FIDs. Check 2
	# 5. Valid FID, points to some other file. Check 3

	# Check 1
	[ ${#fid_list[@]} -ne $fcount ] &&
		error "${#fid_list[@]} != $fcount open files"

	for (( i = 0; i < $fcount; i++ )) ; do
		cmd="exec ${fd_list[i]}</dev/null"
		eval $cmd
		filename=$($LFS fid2path $DIR2 ${fid_list[i]})

		# Check 2
		rm --interactive=no $filename
		[ $? -ne 0 ] &&
			error "Nonexisting fid ${fid_list[i]} listed."
	done

	# Check 3
	ls_op=$(ls $DIR2/$tdir | wc -l)
	[ $ls_op -ne 0 ] &&
		error "Some openfiles are missing in lproc output"

	rm -rf $DIR/$tdir
}
run_test 76 "Verify open file for 2048 files"

test_80() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	local MDTIDX=1
	local mdt_index
	local i
	local file
	local pid

	mkdir -p $DIR1/$tdir/dir
	createmany -o $DIR1/$tdir/dir/f 10 ||
		error "create files under remote dir failed $i"

	cp /etc/passwd $DIR1/$tdir/$tfile

	#migrate open file should fails
	multiop_bg_pause $DIR2/$tdir/$tfile O_c || error "open $file failed"
	pid=$!
	# give multiop a chance to open
	sleep 1

	$LFS mv -M $MDTIDX $DIR1/$tdir &&
		error "migrate open files should failed with open files"

	kill -USR1 $pid

	$LFS mv -M $MDTIDX $DIR1/$tdir ||
			error "migrate remote dir error"

	echo "Finish migration, then checking.."
	for file in $(find $DIR1/$tdir); do
		mdt_index=$($LFS getstripe -M $file)
		[ $mdt_index == $MDTIDX ] ||
			error "$file is not on MDT${MDTIDX}"
	done

	diff /etc/passwd $DIR1/$tdir/$tfile ||
		error "file different after migration"

	rm -rf $DIR1/$tdir || error "rm dir failed after migration"
}
run_test 80 "migrate directory when some children is being opened"

test_81() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	rm -rf $DIR1/$tdir

	mkdir -p $DIR1/$tdir

	$LFS setdirstripe -i0 -c$MDSCOUNT  $DIR1/$tdir/d0
	$LFS setdirstripe -i0 -c$MDSCOUNT  $DIR1/$tdir/d1

	cd $DIR1/$tdir
	touch d0/0	|| error "create 0 failed"
	mv d0/0	d1/0	|| error "rename d0/0 d1/0 failed"
	stat d0/0	&& error "stat mv filed succeed"
	mv $DIR2/$tdir/d1/0 $DIR2/$tdir/d0/0 || "rename d1/0 d0/0 failed"
	stat d0/0	|| error "stat failed"

	local t=$(ls -ai $DIR1/$tdir/d0 | sort -u | wc -l)

	if [ $t -ne 3 ]; then
		ls -ai $DIR1/$tdir/d0
		error "expect 3 get $t"
	fi

	return 0
}
run_test 81 "rename and stat under striped directory"

test_82() {
	# Client 1 creates a file.
	multiop_bg_pause $DIR1/$tfile O_ac || error "multiop_bg_pause 1"
	pid1=$!
	# Client 2 opens the file.
	multiop_bg_pause $DIR2/$tfile o_Ac || error "multiop_bg_pause 2"
	pid2=$!
	# Client 1 makes the file an orphan.
	rm $DIR1/$tfile || error "rm"
	# Client 2 sets EA "user.multiop".
	kill -s USR1 $pid2
	wait $pid2 || error "multiop 2"
	# Client 1 gets EA "user.multiop".  This used to fail because the EA
	# cache refill would get "trusted.link" from mdd_xattr_list() but
	# -ENOENT when trying to get "trusted.link"'s value.  See also sanity
	# 102q.
	kill -s USR1 $pid1
	wait $pid1 || error "multiop 1"
}
run_test 82 "fsetxattr and fgetxattr on orphan files"

log "cleanup: ======================================================"

[ "$(mount | grep $MOUNT2)" ] && umount $MOUNT2

complete $SECONDS
rm -f $SAMPLE_FILE
check_and_cleanup_lustre
exit_status
