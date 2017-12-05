#!/bin/bash

set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: LU-1205 9977/LU-7105 LU-9452
ALWAYS_EXCEPT="                18c     28           29      $SANITYN_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

SRCDIR=$(dirname $0)
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
# bug number for skipped test:        LU-2776
	ALWAYS_EXCEPT="$ALWAYS_EXCEPT 51a"
# LU-2829 / LU-2887 - make allowances for ZFS slowness
	TEST33_NFILES=${TEST33_NFILES:-1000}
fi
#                                  23   (min)"
[ "$SLOW" = "no" ] && EXCEPT_SLOW="33a"

FAIL_ON_ERROR=false

SETUP=${SETUP:-:}
TRACE=${TRACE:-""}

check_and_setup_lustre

assert_DIR
rm -rf $DIR1/[df][0-9]* $DIR1/lnk $DIR/[df].${TESTSUITE}*

SAMPLE_FILE=$TMP/$(basename $0 .sh).junk
dd if=/dev/urandom of=$SAMPLE_FILE bs=1M count=1

# $RUNAS_ID may get set incorrectly somewhere else
[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] && error "\$RUNAS_ID set to 0, but \$UID is also 0!"

check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

build_test_filter

test_1() {
	touch $DIR1/$tfile
	[ -f $DIR2/$tfile ] || error "Check create"
	chmod 777 $DIR2/$tfile
	$CHECKSTAT -t file -p 0777 $DIR1/$tfile ||
		error "Check attribute update for 0777"

	chmod a-x $DIR2/$tfile
	$CHECKSTAT -t file -p 0666 $DIR1/$tfile ||
		error "Check attribute update for 0666"

	rm $DIR2/$tfile
	$CHECKSTAT -a $DIR1/$tfile ||
		error "Check unlink - removes file on other mountpoint"
}
run_test 1 "Check attribute updates on 2 mount points"

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

test_2g() {
	dd if=/dev/zero of=$DIR1/$tfile oflag=sync bs=1M count=2

	local block1=$(stat $DIR1/$tfile | awk '/Blocks/ {print $4} ')
	cancel_lru_locks osc
	local block2=$(stat $DIR2/$tfile | awk '/Blocks/ {print $4} ')
	echo "$DIR1/$tfile has $block1 blocks"
	echo "$DIR2/$tfile has $block2 blocks"
	[ $block1 -eq $block2 ] || error
}
run_test 2g "check blocks update on sync write"

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

test_14aa() {
	test_mkdir -p $DIR1/$tdir
	cp -p /bin/ls $DIR1/$tdir/$tfile
	multiop_bg_pause $DIR1/$tdir/$tfile Ow_c || return 1
	MULTIPID=$!

	$DIR2/$tdir/$tfile && error || true
	kill -USR1 $MULTIPID
	wait $MULTIPID || return 2
}
run_test 14aa "execution of file open for write returns -ETXTBSY"

test_14ab() {
	test_mkdir -p $DIR1/d14
	cp -p `which multiop` $DIR1/d14/multiop || error "cp failed"
        MULTIOP_PROG=$DIR1/d14/multiop multiop_bg_pause $TMP/test14.junk O_c || return 1
        MULTIOP_PID=$!
        $MULTIOP $DIR2/d14/multiop Oc && error "expected error, got success"
        kill -USR1 $MULTIOP_PID || return 2
        wait $MULTIOP_PID || return 3
        rm $TMP/test14.junk $DIR1/d14/multiop || error "removing multiop"
}
run_test 14ab "open(RDWR) of executing file returns -ETXTBSY"

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
	clear_stats osc.*.osc_stats

	log "checking cached lockless truncate"
	$TRUNCATE $DIR1/$tfile 8000000
	$CHECKSTAT -s 8000000 $DIR2/$tfile || error "wrong file size"
	[ $(calc_stats osc.*.osc_stats lockless_truncate) -ne 0 ] ||
		error "cached truncate isn't lockless"

	log "checking not cached lockless truncate"
	$TRUNCATE $DIR2/$tfile 5000000
	$CHECKSTAT -s 5000000 $DIR1/$tfile || error "wrong file size"
	[ $(calc_stats osc.*.osc_stats lockless_truncate) -ne 0 ] ||
		error "not cached truncate isn't lockless"

	log "disabled lockless truncate"
	enable_lockless_truncate 0
	clear_stats osc.*.osc_stats
	$TRUNCATE $DIR2/$tfile 3000000
	$CHECKSTAT -s 3000000 $DIR1/$tfile || error "wrong file size"
	[ $(calc_stats osc.*.osc_stats lockless_truncate) -eq 0 ] ||
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
	clear_stats osc.*.osc_stats

	# agressive lockless i/o settings
	do_nodes $(comma_list $(osts_nodes)) \
		"lctl set_param -n ldlm.namespaces.*.max_nolock_bytes=2000000 \
			ldlm.namespaces.filter-*.contended_locks=0 \
			ldlm.namespaces.filter-*.contention_seconds=60"
	lctl set_param -n osc.*.contention_seconds=60
	for i in {1..5}; do
		dd if=/dev/zero of=$DIR1/$tfile bs=4k count=1 conv=notrunc > \
			/dev/null 2>&1
		dd if=/dev/zero of=$DIR2/$tfile bs=4k count=1 conv=notrunc > \
			/dev/null 2>&1
	done
	[ $(calc_stats osc.*.osc_stats lockless_write_bytes) -ne 0 ] ||
		error "lockless i/o was not triggered"
	# disable lockless i/o (it is disabled by default)
	do_nodes $(comma_list $(osts_nodes)) \
		"lctl set_param -n ldlm.namespaces.filter-*.max_nolock_bytes=0 \
			ldlm.namespaces.filter-*.contended_locks=32 \
			ldlm.namespaces.filter-*.contention_seconds=0"
	# set contention_seconds to 0 at client too, otherwise Lustre still
	# remembers lock contention
	lctl set_param -n osc.*.contention_seconds=0
	clear_stats osc.*.osc_stats
	for i in {1..1}; do
		dd if=/dev/zero of=$DIR1/$tfile bs=4k count=1 conv=notrunc > \
			/dev/null 2>&1
		dd if=/dev/zero of=$DIR2/$tfile bs=4k count=1 conv=notrunc > \
			/dev/null 2>&1
	done
	[ $(calc_stats osc.*.osc_stats lockless_write_bytes) -eq 0 ] ||
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
            local elapsed=$(do_and_time "do_nodes $CLIENT1,$CLIENT2 createmany -o $DIR1/$tdir-\\\$(hostname)-$i/f- -r$DIR2/$tdir-\\\$(hostname)-$i/f- $nfiles > /dev/null 2>&1")
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
			do_node $CLIENT1 "$LFS mkdir -i $MDTIDX \
					  $DIR1/$tdir-\\\$(hostname)-$i"

			jbdold=$(print_jbd_stat)
			echo "=== START createmany old: $jbdold transaction"
			local elapsed=$(do_and_time "do_nodes $CLIENT1,$CLIENT2\
				createmany -o $DIR1/$tdir-\\\$(hostname)-$i/f- \
				-r$DIR2/$tdir-\\\$(hostname)-$i/f- $nfiles > \
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

test_33c() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.7.63) ] &&
		skip "DNE CoS not supported" && return

	sync

	mkdir $DIR/$tdir
	# remote mkdir is done on MDT2, which enqueued lock of $tdir on MDT1
	$LFS mkdir -i 1 $DIR/$tdir/d1
	do_facet mds1 "lctl set_param -n mdt.*.sync_count=0"
	mkdir $DIR/$tdir/d2
	local sync_count=$(do_facet mds1 \
		"lctl get_param -n mdt.*MDT0000.sync_count")
	[ $sync_count -eq 1 ] || error "Sync-Lock-Cancel not triggered"

	$LFS mkdir -i 1 $DIR/$tdir/d3
	do_facet mds1 "lctl set_param -n mdt.*.sync_count=0"
	# during sleep remote mkdir should have been committed and canceled
	# remote lock spontaneously, which shouldn't trigger sync
	sleep 6
	mkdir $DIR/$tdir/d4
	local sync_count=$(do_facet mds1 \
		"lctl get_param -n mdt.*MDT0000.sync_count")
	[ $sync_count -eq 0 ] || error "Sync-Lock-Cancel triggered"
}
run_test 33c "Cancel cross-MDT lock should trigger Sync-Lock-Cancel"

ops_do_cos() {
	local nodes=$(comma_list $(mdts_nodes))
	do_nodes $nodes "lctl set_param -n mdt.*.async_commit_count=0"
	sh -c "$@"
	local async_commit_count=$(do_nodes $nodes \
		"lctl get_param -n mdt.*.async_commit_count" | calc_sum)
	[ $async_commit_count -gt 0 ] || error "CoS not triggerred"

	rm -rf $DIR/$tdir
	sync
}

test_33d() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.7.63) ] &&
		skip "DNE CoS not supported" && return

	sync
	# remote directory create
	mkdir $DIR/$tdir
	ops_do_cos "$LFS mkdir -i 1 $DIR/$tdir/subdir"
	# remote directory unlink
	$LFS mkdir -i 1 $DIR/$tdir
	ops_do_cos "rmdir $DIR/$tdir"
	# striped directory create
	mkdir $DIR/$tdir
	ops_do_cos "$LFS mkdir -c 2 $DIR/$tdir/subdir"
	# striped directory setattr
	$LFS mkdir -c 2 $DIR/$tdir
	touch $DIR/$tdir
	ops_do_cos "chmod 713 $DIR/$tdir"
	# striped directory unlink
	$LFS mkdir -c 2 $DIR/$tdir
	touch $DIR/$tdir
	ops_do_cos "rmdir $DIR/$tdir"
	# cross-MDT link
	$LFS mkdir -c 2 $DIR/$tdir
	$LFS mkdir -i 0 $DIR/$tdir/d1
	$LFS mkdir -i 1 $DIR/$tdir/d2
	touch $DIR/$tdir/d1/tgt
	ops_do_cos "ln $DIR/$tdir/d1/tgt $DIR/$tdir/d2/src"
	# cross-MDT rename
	$LFS mkdir -c 2 $DIR/$tdir
	$LFS mkdir -i 0 $DIR/$tdir/d1
	$LFS mkdir -i 1 $DIR/$tdir/d2
	touch $DIR/$tdir/d1/src
	ops_do_cos "mv $DIR/$tdir/d1/src $DIR/$tdir/d2/tgt"
	# migrate
	$LFS mkdir -i 0 $DIR/$tdir
	ops_do_cos "$LFS migrate -m 1 $DIR/$tdir"
	return 0
}
run_test 33d "DNE distributed operation should trigger COS"

test_33e() {
	[ -n "$CLIENTS" ] || { skip "Need two or more clients" && return 0; }
	[ $CLIENTCOUNT -ge 2 ] ||
		{ skip "Need two or more clients, have $CLIENTCOUNT" &&
								return 0; }
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.7.63) ] &&
		skip "DNE CoS not supported" && return

	local client2=${CLIENT2:-$(hostname)}

	sync

	local nodes=$(comma_list $(mdts_nodes))
	do_nodes $nodes "lctl set_param -n mdt.*.async_commit_count=0"

	$LFS mkdir -c 2 $DIR/$tdir
	mkdir $DIR/$tdir/subdir
	echo abc > $DIR/$tdir/$tfile
	do_node $client2 echo dfg >> $DIR/$tdir/$tfile
	do_node $client2 touch $DIR/$tdir/subdir

	local async_commit_count=$(do_nodes $nodes \
		"lctl get_param -n mdt.*.async_commit_count" | calc_sum)
	[ $async_commit_count -gt 0 ] && error "CoS triggerred"

	return 0
}
run_test 33e "DNE local operation shouldn't trigger COS"

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
	remote_ost_nodsh && skip "remote OST with nodsh" && return
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
	sync; sleep 2; sync # wait for delete thread
	wait_mds_ost_sync || error "wait_mds_ost_sync failed"
	wait_destroy_complete || error "wait_destroy_complete failed"

	while [ $i -le 10 ]; do
		lctl mark "start test - cycle ($i)"
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
		sync; sleep 2; sync # Ensure new statfs
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

test_39d() { # LU-7310
	touch $DIR1/$tfile
	touch -m -d @$TEST_39_MTIME $DIR1/$tfile

	local mtime1=$(stat -c %Y $DIR2/$tfile)
	[ "$mtime1" = $TEST_39_MTIME ] ||
		error "mtime: $mtime1, should be $TEST_39_MTIME"

	# force sync write
	# define OBD_FAIL_OSC_NO_GRANT 0x411
	$LCTL set_param fail_loc=0x411

	local d1=$(date +%s)
	echo hello >> $DIR1/$tfile
	local d2=$(date +%s)

	$LCTL set_param fail_loc=0

	cancel_lru_locks osc

	local mtime2=$(stat -c %Y $DIR2/$tfile)
	[ "$mtime2" -ge "$d1" ] && [ "$mtime2" -le "$d2" ] ||
		error "mtime is not updated on write: $d1 <= $mtime2 <= $d2"
}
run_test 39d "sync write should update mtime"

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
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	touch $DIR2
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

	#  all operations above shouldn't wait the first one
	check_pdo_conflict $PID1 || error "parallel operation is blocked"
	wait $PID1
	rm -rf $DIR/$tfile*
	return 0
}
run_test 40a "pdirops: create vs others =============="

test_40b() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
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
	rm -rf $DIR/$tfile*
	return 0
}
run_test 40b "pdirops: open|create and others =============="

test_40c() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
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
	rm -rf $DIR/$tfile*
	return 0
}
run_test 40c "pdirops: link and others =============="

test_40d() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
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
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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
	rm -rf $DIR/$tfile*
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

	filesize=$(stat -c %s $origfile)

	# create an empty file
	$MCREATE $DIR1/$tfile || error "can't create $DIR1/$tfile"
	# cache layout lock on both mount point
	stat $DIR1/$tfile > /dev/null || error "stat $DIR1/$tfile failed"
	stat $DIR2/$tfile > /dev/null || error "stat $DIR2/$tfile failed"

	# open and sleep 2 seconds then read
	$MULTIOP $DIR2/$tfile o_2r${filesize}c &
	local pid=$!
	sleep 1

	# create the layout of testing file
	dd if=$origfile of=$DIR1/$tfile conv=notrunc > /dev/null ||
		error "dd $DIR1/$tfile failed"

	# MULTIOP proc should be able to read enough bytes and exit
	sleep 2
	kill -0 $pid 2> /dev/null && error "multiop is still there"
	cmp $origfile $DIR2/$tfile || error "$origfile and $DIR2/$tfile differs"

	rm -f $DIR1/$tfile
}
run_test 51a "layout lock: refresh layout should work"

test_51b() {
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.3.59) ]] ||
		{ skip "Need MDS version at least 2.3.59"; return 0; }

	local tmpfile=`mktemp`

	# create an empty file
	$MCREATE $DIR1/$tfile || error "mcreate $DIR1/$tfile failed"

	# delay glimpse so that layout has changed when glimpse finish
#define OBD_FAIL_GLIMPSE_DELAY 0x1404
	$LCTL set_param fail_loc=0x1404
	stat -c %s $DIR2/$tfile |tee $tmpfile &
	local pid=$!
	sleep 1

	# create layout of testing file
	dd if=/dev/zero of=$DIR1/$tfile bs=1k count=1 conv=notrunc >/dev/null ||
		error "dd $DIR1/$tfile failed"

	wait $pid
	local fsize=$(cat $tmpfile)

	[ x$fsize = x1024 ] || error "file size is $fsize, should be 1024"

	rm -f $DIR1/$tfile $tmpfile
}
run_test 51b "layout lock: glimpse should be able to restart if layout changed"

test_51c() {
	[ $OSTCOUNT -ge 2 ] || { skip "needs >= 2 osts"; return; }

	# set default layout to have 1 stripe
	mkdir $DIR1/$tdir
	$LFS setstripe -c 1 $DIR1/$tdir

	# create a file with empty layout
	$MCREATE $DIR1/$tdir/$tfile ||
		error "$MCREATE $DIR1/$tdir/$tfile failed"

#define OBD_FAIL_MDS_LL_BLOCK 0x172
	do_facet $SINGLEMDS $LCTL set_param fail_loc=0x172

	# change the layout of testing file
	echo "Setting layout to have $OSTCOUNT stripes ..."
	$LFS setstripe -c $OSTCOUNT $DIR1/$tdir/$tfile &
	pid=$!
	sleep 1

	# write something to the file, it should be blocked on fetching layout
	dd if=/dev/zero of=$DIR2/$tdir/$tfile bs=1k count=1 conv=notrunc
	local stripecnt=$($LFS getstripe -c $DIR2/$tdir/$tfile)
	wait $pid

	# lod_qos.c::min_stripe_count() allows setstripe with a default stripe
	# count to succeed with only 3/4 of the number of stripes (rounded up),
	# so creating striped files does not fail if an OST is offline or full
	[ $stripecnt -ge $((OSTCOUNT - $OSTCOUNT / 4)) ] ||
		error "layout wrong: getstripe -c $stripecnt < $OSTCOUNT * 3/4"

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

	do_facet mds1 $LCTL set_param fail_loc=$1

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

	do_facet mds1 $LCTL set_param fail_loc=$1

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
	do_facet mds1 $LCTL set_param fail_loc=0x80000156

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
	do_facet mds1 $LCTL set_param fail_loc=0x80000156

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
	do_facet mds1 $LCTL set_param fail_loc=0x156

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
	do_facet mds1 $LCTL set_param fail_loc=0x155
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
	local MDSVER=$(lustre_build_version $SINGLEMDS)
	[ $(version_code $MDSVER) -lt $(version_code 2.3.0) ] &&
		skip "MDS version $MDSVER must be >= 2.3.0" && return 0

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

test_71a() {
	local server_version=$(lustre_version_code $SINGLEMDS)

	[[ $server_version -lt $(version_code 2.1.6) ]] &&
		skip "Need MDS version at least 2.1.6" && return

	# Patch not applied to 2.2 and 2.3 branches
	[[ $server_version -ge $(version_code 2.2.0) ]] &&
	[[ $server_version -lt $(version_code 2.4.0) ]] &&
		skip "Need MDS version earlier than 2.2.0 or at least 2.4.0" &&
			return

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
run_test 71a "correct file map just after write operation is finished"

test_71b() {
	local server_version=$(lustre_version_code $SINGLEMDS)

	[[ $server_version -lt $(version_code 2.1.6) ]] &&
		skip "Need MDS version at least 2.1.6" && return

	# Patch not applied to 2.2 and 2.3 branches
	[[ $server_version -ge $(version_code 2.2.0) ]] &&
	[[ $server_version -lt $(version_code 2.4.0) ]] &&
		skip "Need MDS version earlier than 2.2.0 or at least 2.4.0" &&
			return
	[[ $OSTCOUNT -ge 2 ]] || { skip "needs >= 2 OSTs"; return; }

	checkfiemap --test ||
		{ skip "error $?: checkfiemap failed" && return; }

	mkdir -p $DIR1/$tdir

	$LFS setstripe -c -1 $DIR1/$tdir || error "setstripe failed"
	dd if=/dev/urandom of=$DIR1/$tdir/$tfile bs=40K count=1
	[ "$(facet_fstype ost$(($($GETSTRIPE -i $DIR1/$tdir/$tfile) + 1)))" = \
		"zfs" ] &&
		skip "ORI-366/LU-1941: FIEMAP unimplemented on ZFS" && return 0
	checkfiemap $DIR1/$tdir/$tfile 40960 || error "checkfiemap failed"
}
run_test 71b "check fiemap support for stripecount > 1"

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
	clear_stats llite.*.stats
	# PR lock should be cached by now on both clients
	getfattr -n user.attr1 $DIR1/$tfile || error "getfattr3 failed"
	# 2 hits for getfattr(0)+getfattr(size)
	[ $(calc_stats llite.*.stats getxattr_hits) -eq 2 ] ||
		error "not cached in $DIR1"
	getfattr -n user.attr1 $DIR2/$tfile || error "getfattr4 failed"
	# 4 hits for more getfattr(0)+getfattr(size)
	[ $(calc_stats llite.*.stats getxattr_hits) -eq 4 ] ||
		error "not cached in $DIR2"
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
	local fcount=$((MDSCOUNT * 256))
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

	local open_fids_cmd="$LCTL get_param -n mdt.*.exports.'$nid'.open_files"
	local fid_list=($(do_nodes $(comma_list $(mdts_nodes)) $open_fids_cmd))
	local already=${#fid_list[@]}
	for (( i = 0; i < $already; i++ )) ; do
		log "already open[$i]: $($LFS fid2path $DIR2 ${fid_list[i]})"
	done

	echo -n "opening files: "
	ulimit -n $((fcount + 50))
	for ((i = 0; i < $fcount; i++)); do
		touch $DIR/$tdir/f_$i
		local fd=$(free_fd ${fd_list[i]})
		local open_cmd="exec $fd<$DIR/$tdir/f_$i"
		eval $open_cmd

		fd_list[i]=$fd

		(( $i % 32 == 0 )) && echo -n "."
	done
	echo

	fid_list=($(do_nodes $(comma_list $(mdts_nodes)) $open_fids_cmd))

	# Possible errors in openfiles FID list.
	# 1. Missing FIDs. Check 1
	# 2. Extra FIDs. Check 1
	# 3. Duplicated FID. Check 2
	# 4. Invalid FIDs. Check 2
	# 5. Valid FID, points to some other file. Check 3

	# Check 1
	[ ${#fid_list[@]} -ne $((fcount + already)) ] &&
		error "${#fid_list[@]} != $fcount (+$already old) open files"

	echo -n "closing files: "
	for (( fd = 0, fid = 0; fd < $fcount; fd++, fid++ )) ; do
		local close_cmd="exec ${fd_list[fd]}<&-"
		eval $close_cmd
		filename=$($LFS fid2path $DIR2 ${fid_list[fid]})

		while [[ ! "$filename" =~ "$DIR2/$tdir/f_" ]]; do
			echo "skip old open file $filename"
			((fid++))
			filename=$($LFS fid2path $DIR2 ${fid_list[fid]})
		done

		# Check 2
		rm --interactive=no $filename
		[ $? -ne 0 ] &&
			error "Nonexisting fid ${fid_list[fid]} listed."
		(( $fd % 32 == 0 )) && echo -n "."
	done
	echo

	# Check 3
	ls_op=$(ls $DIR2/$tdir | wc -l)
	[ $ls_op -ne 0 ] &&
		error "Some openfiles are missing in lproc output"

	rm -rf $DIR/$tdir
}
run_test 76 "Verify MDT open_files listing"

nrs_write_read() {
	local n=16
	local dir=$DIR/$tdir
	local myRUNAS="$1"

	mkdir $dir || error "mkdir $dir failed"
	$LFS setstripe -c $OSTCOUNT $dir || error "setstripe to $dir failed"
	chmod 777 $dir

	do_nodes $CLIENTS $myRUNAS \
		dd if=/dev/zero of="$dir/nrs_r_$HOSTNAME" bs=1M count=$n ||
		error "dd at 0 on client failed (1)"

	for ((i = 0; i < $n; i++)); do
		do_nodes $CLIENTS $myRUNAS dd if=/dev/zero \
			of="$dir/nrs_w_$HOSTNAME" bs=1M seek=$i count=1 ||
			 error "dd at ${i}MB on client failed (2)" &
		local pids_w[$i]=$!
	done
	do_nodes $CLIENTS sync;
	cancel_lru_locks osc

	for ((i = 0; i < $n; i++)); do
		do_nodes $CLIENTS $myRUNAS dd if="$dir/nrs_w_$HOSTNAME" \
			of=/dev/zero bs=1M seek=$i count=1 > /dev/null ||
			error "dd at ${i}MB on client failed (3)" &
		local pids_r[$i]=$!
	done
	cancel_lru_locks osc

	for ((i = 0; i < $n; i++)); do
		wait ${pids_w[$i]}
		wait ${pids_r[$i]}
	done
	rm -rf $dir || error "rm -rf $dir failed"
}

test_77a() { #LU-3266
	oss=$(comma_list $(osts_nodes))
	do_nodes $oss lctl set_param ost.OSS.*.nrs_policies="fifo"
	nrs_write_read

	return 0
}
run_test 77a "check FIFO NRS policy"

test_77b() { #LU-3266
	oss=$(comma_list $(osts_nodes))

	do_nodes $oss lctl set_param ost.OSS.*.nrs_policies="crrn" \
			   ost.OSS.*.nrs_crrn_quantum=1

	echo "policy: crr-n, crrn_quantum 1"
	nrs_write_read

	do_nodes $oss lctl set_param ost.OSS.*.nrs_crrn_quantum=64

	echo "policy: crr-n, crrn_quantum 64"
	nrs_write_read

	# cleanup
	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="fifo"
	return 0
}
run_test 77b "check CRR-N NRS policy"

orr_trr() {
	local policy=$1

	oss=$(comma_list $(osts_nodes))

	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies=$policy \
				     ost.OSS.*.nrs_"$policy"_quantum=1 \
				     ost.OSS.*.nrs_"$policy"_offset_type="physical" \
				     ost.OSS.*.nrs_"$policy"_supported="reads"

	echo "policy: $policy, ${policy}_quantum 1, ${policy}_offset_type physical, ${policy}_supported reads"
	nrs_write_read

	do_nodes $oss lctl set_param ost.OSS.*.nrs_${policy}_supported="writes" \
				     ost.OSS.*.nrs_${policy}_quantum=64

	echo "policy: $policy, ${policy}_quantum 64, ${policy}_offset_type physical, ${policy}_supported writes"
	nrs_write_read

	do_nodes $oss lctl set_param ost.OSS.*.nrs_${policy}_supported="reads_and_writes" \
				     ost.OSS.*.nrs_${policy}_offset_type="logical"
	echo "policy: $policy, ${policy}_quantum 64, ${policy}_offset_type logical, ${policy}_supported reads_and_writes"
	nrs_write_read

	# cleanup
	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="fifo"
	return 0
}

test_77c() { #LU-3266
	orr_trr "orr"
	return 0
}
run_test 77c "check ORR NRS policy"

test_77d() { #LU-3266
	orr_trr "trr"
	return 0
}
run_test 77d "check TRR nrs policy"

tbf_rule_operate()
{
	local facet=$1
	shift 1

	do_facet $facet lctl set_param \
		ost.OSS.ost_io.nrs_tbf_rule="$*"
	[ $? -ne 0 ] &&
		error "failed to run operate '$*' on TBF rules"
}

cleanup_tbf_verify()
{
	local rc=0
	trap 0
	echo "cleanup_tbf $DIR/$tdir"
	rm -rf $DIR/$tdir
	rc=$?
	wait_delete_completed
	return $rc
}

tbf_verify() {
	local dir=$DIR/$tdir
	local client1=${CLIENT1:-$(hostname)}
	local myRUNAS="$3"

	local np=$(check_cpt_number ost1)
	[ $np -gt 0 ] || error "CPU partitions should not be $np."
	echo "cpu_npartitions on ost1 is $np"

	mkdir $dir || error "mkdir $dir failed"
	$LFS setstripe -c 1 -i 0 $dir || error "setstripe to $dir failed"
	chmod 777 $dir

	trap cleanup_tbf_verify EXIT
	echo "Limited write rate: $1, read rate: $2"
	echo "Verify the write rate is under TBF control"
	local start=$SECONDS
	do_node $client1 $myRUNAS dd if=/dev/zero of=$dir/tbf \
		bs=1M count=100 oflag=direct 2>&1
	local runtime=$((SECONDS - start + 1))
	local rate=$(bc <<< "scale=6; 100 / $runtime")
	echo "Write runtime is $runtime s, speed is $rate IOPS"

	# verify the write rate does not exceed TBF rate limit
	[ $(bc <<< "$rate < 1.1 * $np * $1") -eq 1 ] ||
		error "The write rate ($rate) exceeds 110% of rate limit ($1 * $np)"

	cancel_lru_locks osc

	echo "Verify the read rate is under TBF control"
	start=$SECONDS
	do_node $client1 $myRUNAS dd if=$dir/tbf of=/dev/null \
		bs=1M count=100 iflag=direct 2>&1
	runtime=$((SECONDS - start + 1))
	rate=$(bc <<< "scale=6; 100 / $runtime")
	echo "Read runtime is $runtime s, speed is $rate IOPS"

	# verify the read rate does not exceed TBF rate limit
	[ $(bc <<< "$rate < 1.1 * $np * $2") -eq 1 ] ||
		error "The read rate ($rate) exceeds 110% of rate limit ($2 * $np)"

	cancel_lru_locks osc
	cleanup_tbf_verify || error "rm -rf $dir failed"
}

test_77e() {
	local server_version=$(lustre_version_code ost1)
	[[ $server_version -ge $(version_code 2.7.58) ]] ||
		{ skip "Need server version newer than 2.7.57"; return 0; }

	oss=$(comma_list $(osts_nodes))

	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="tbf\ nid"
	[ $? -ne 0 ] && error "failed to set TBF policy"

	local idis
	local rateis
	if [ $(lustre_version_code ost1) -ge $(version_code 2.8.54) ]; then
		idis="nid="
		rateis="rate="
	fi

	# Only operate rules on ost1 since OSTs might run on the same OSS
	# Add some rules
	tbf_rule_operate ost1 "start\ localhost\ ${idis}{0@lo}\ ${rateis}1000"
	local address=$(comma_list "$(host_nids_address $CLIENTS $NETTYPE)")
	local client_nids=$(nids_list $address "\\")
	tbf_rule_operate ost1 "start\ clients\ ${idis}{$client_nids}\ ${rateis}100"
	tbf_rule_operate ost1 "start\ others\ ${idis}{*.*.*.*@$NETTYPE}\ ${rateis}50"
	nrs_write_read

	# Change the rules
	tbf_rule_operate ost1 "change\ localhost\ ${rateis}1001"
	tbf_rule_operate ost1 "change\ clients\ ${rateis}101"
	tbf_rule_operate ost1 "change\ others\ ${rateis}51"
	nrs_write_read

	# Stop the rules
	tbf_rule_operate ost1 "stop\ localhost"
	tbf_rule_operate ost1 "stop\ clients"
	tbf_rule_operate ost1 "stop\ others"
	nrs_write_read

	# Cleanup the TBF policy
	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="fifo"
	[ $? -ne 0 ] && error "failed to set policy back to fifo"
	nrs_write_read
	return 0
}
run_test 77e "check TBF NID nrs policy"

test_77f() {
	local server_version=$(lustre_version_code ost1)
	[[ $server_version -ge $(version_code 2.7.58) ]] ||
		{ skip "Need server version newer than 2.7.57"; return 0; }

	oss=$(comma_list $(osts_nodes))

	# Configure jobid_var
	local saved_jobid_var=$($LCTL get_param -n jobid_var)
	if [ $saved_jobid_var != procname_uid ]; then
		set_conf_param_and_check client			\
			"$LCTL get_param -n jobid_var"		\
			"$FSNAME.sys.jobid_var" procname_uid
	fi

	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="tbf\ jobid"
	[ $? -ne 0 ] && error "failed to set TBF policy"

	local idis
	local rateis
	if [ $(lustre_version_code ost1) -ge $(version_code 2.8.54) ]; then
		idis="jobid="
		rateis="rate="
	fi

	# Only operate rules on ost1 since OSTs might run on the same OSS
	# Add some rules
	tbf_rule_operate ost1 "start\ runas\ ${idis}{iozone.$RUNAS_ID\ dd.$RUNAS_ID\ tiotest.$RUNAS_ID}\ ${rateis}1000"
	tbf_rule_operate ost1 "start\ iozone_runas\ ${idis}{iozone.$RUNAS_ID}\ ${rateis}100"
	tbf_rule_operate ost1 "start\ dd_runas\ ${idis}{dd.$RUNAS_ID}\ ${rateis}50"
	nrs_write_read "$RUNAS"

	# Change the rules
	tbf_rule_operate ost1 "change\ runas\ ${rateis}1001"
	tbf_rule_operate ost1 "change\ iozone_runas\ ${rateis}101"
	tbf_rule_operate ost1 "change\ dd_runas\ ${rateis}51"
	nrs_write_read "$RUNAS"

	# Stop the rules
	tbf_rule_operate ost1 "stop\ runas"
	tbf_rule_operate ost1 "stop\ iozone_runas"
	tbf_rule_operate ost1 "stop\ dd_runas"
	nrs_write_read "$RUNAS"

	# Cleanup the TBF policy
	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="fifo"
	[ $? -ne 0 ] && error "failed to set policy back to fifo"
	nrs_write_read "$RUNAS"

	local current_jobid_var=$($LCTL get_param -n jobid_var)
	if [ $saved_jobid_var != $current_jobid_var ]; then
		set_conf_param_and_check client			\
			"$LCTL get_param -n jobid_var"		\
			"$FSNAME.sys.jobid_var" $saved_jobid_var
	fi
	return 0
}
run_test 77f "check TBF JobID nrs policy"

test_77g() {
	local server_version=$(lustre_version_code ost1)
	[[ $server_version -ge $(version_code 2.7.58) ]] ||
		{ skip "Need server version newer than 2.7.57"; return 0; }

	oss=$(comma_list $(osts_nodes))

	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="tbf\ nid"
	[ $? -ne 0 ] && error "failed to set TBF policy"

	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="tbf\ jobid"
	[ $? -ne 0 ] && error "failed to set TBF policy"

	local idis
	local rateis
	if [ $(lustre_version_code ost1) -ge $(version_code 2.8.54) ]; then
		idis="jobid="
		rateis="rate="
	fi

	# Add a rule that only valid for Jobid TBF. If direct change between
	# TBF types is not supported, this operation will fail.
	tbf_rule_operate ost1 "start\ dd_runas\ ${idis}{dd.$RUNAS_ID}\ ${rateis}50"

	# Cleanup the TBF policy
	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="fifo"
	[ $? -ne 0 ] && error "failed to set policy back to fifo"
	return 0
}
run_test 77g "Change TBF type directly"

test_77h() {
	[ $(lustre_version_code ost1) -ge $(version_code 2.8.55) ] ||
		{ skip "Need OST version at least 2.8.55"; return 0; }

	local old_policy=$(do_facet ost1 \
		lctl get_param ost.OSS.ost_io.nrs_policies)
	local new_policy

	do_facet ost1 lctl set_param \
		ost.OSS.ost_io.nrs_policies="abc"
	[ $? -eq 0 ] && error "should return error"

	do_facet ost1 lctl set_param \
		ost.OSS.ost_io.nrs_policies="tbf\ abc"
	[ $? -eq 0 ] && error "should return error"

	do_facet ost1 lctl set_param \
		ost.OSS.ost_io.nrs_policies="tbf\ reg\ abc"
	[ $? -eq 0 ] && error "should return error"

	do_facet ost1 lctl set_param \
		ost.OSS.ost_io.nrs_policies="tbf\ abc\ efg"
	[ $? -eq 0 ] && error "should return error"

	new_policy=$(do_facet ost1 lctl get_param ost.OSS.ost_io.nrs_policies)
	[ $? -eq 0 ] || error "shouldn't LBUG"

	[ "$old_policy" = "$new_policy" ] || error "NRS policy should be same"

	return 0
}
run_test 77h "Wrong policy name should report error, not LBUG"

tbf_rule_check()
{
	local facet=$1
	local expected=$2
	local error_message=$3
	local rule_number=0
	for rule in $expected; do
		rule_number=$((rule_number + 1))
	done
	local stop_line=$(($rule_number + 3))
	local awk_command="awk 'NR >= 4 && NR <= $stop_line {print \$1}'"

	local output=$(do_facet $facet lctl get_param \
		ost.OSS.ost_io.nrs_tbf_rule |
		eval $awk_command |
		tr "\n" " " |
		sed 's/[ ]*$//')
	if [ "$output" != "$expected" ]; then
		error "$error_message, expected '$expected', got '$output'"
	fi
}

test_77i() {
	[ $(lustre_version_code ost1) -ge $(version_code 2.8.55) ] ||
		{ skip "Need OST version at least 2.8.55"; return 0; }

	for i in $(seq 1 $OSTCOUNT)
	do
		do_facet ost"$i" lctl set_param \
			ost.OSS.ost_io.nrs_policies="tbf\ jobid"
		[ $? -ne 0 ] &&
			error "failed to set TBF policy"
	done

	tbf_rule_check ost1 "default" "error before inserting any rule"

	tbf_rule_operate ost1 "start\ before\ jobid={jobid}\ rate=1000"
	tbf_rule_check ost1 "before default" \
		"error when inserting rule 'before'"

	tbf_rule_operate ost1 "start\ after\ jobid={jobid}\ rate=1000\ rank=default"
	tbf_rule_check ost1 "before after default" \
		"error when inserting rule 'after'"

	tbf_rule_operate ost1 "start\ target\ jobid={jobid}\ rate=1000\ rank=after"
	tbf_rule_check ost1 "before target after default" \
		"error when inserting rule 'target'"

	echo "Move before itself"
	tbf_rule_operate ost1 "change\ target\ rank=target"
	tbf_rule_check ost1 "before target after default" \
		"error when moving before itself"

	echo "Move to higher rank"
	tbf_rule_operate ost1 "change\ target\ rank=before"
	tbf_rule_check ost1 "target before after default" \
		"error when moving to higher rank"

	echo "Move to lower rank"
	tbf_rule_operate ost1 "change\ target\ rank=after"
	tbf_rule_check ost1 "before target after default" \
		"error when moving to lower rank"

	echo "Move before default"
	tbf_rule_operate ost1 "change\ target\ rank=default"
	tbf_rule_check ost1 "before after target default" \
		error "error when moving before default"

	# Cleanup the TBF policy
	do_nodes $(comma_list $(osts_nodes)) \
		$LCTL set_param ost.OSS.ost_io.nrs_policies=fifo
	return 0
}
run_test 77i "Change rank of TBF rule"

test_77j() {
	local idis
	local rateis
	local ost_version=$(lustre_version_code ost1)

	[ $ost_version -ge $(version_code 2.9.53) ] ||
		{ skip "Need OST version at least 2.9.53"; return 0; }
	if [ $ost_version -ge $(version_code 2.8.60) ]; then
		idis="opcode="
		rateis="rate="
	fi

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param jobid_var=procname_uid \
			ost.OSS.ost_io.nrs_policies="tbf\ opcode" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ost_r\ ${idis}{ost_read}\ ${rateis}5" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ost_w\ ${idis}{ost_write}\ ${rateis}20"
	[ $? -ne 0 ] && error "failed to set TBF OPCode policy"

	nrs_write_read
	tbf_verify 20 5

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ ost_r" \
			ost.OSS.ost_io.nrs_tbf_rule="stop\ ost_w" \
			ost.OSS.ost_io.nrs_policies="fifo"

	# sleep 3 seconds to wait the tbf policy stop completely,
	# or the next test case is possible get -EAGAIN when
	# setting the tbf policy
	sleep 3
}
run_test 77j "check TBF-OPCode NRS policy"

test_77k() {
	[[ $(lustre_version_code ost1) -ge $(version_code 2.9.53) ]] ||
		{ skip "Need OST version at least 2.9.53"; return 0; }

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_policies="tbf" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_w\ jobid={dd.$RUNAS_ID}\&opcode={ost_write}\ rate=20" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_r\ jobid={dd.$RUNAS_ID}\&opcode={ost_read}\ rate=10"

	nrs_write_read "$RUNAS"
	tbf_verify 20 10 "$RUNAS"

	local address=$(comma_list "$(host_nids_address $CLIENTS $NETTYPE)")
	local client_nids=$(nids_list $address "\\")
	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_w" \
			ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_r" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_w\ nid={0@lo\ $client_nids}\&opcode={ost_write}\ rate=20" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_r\ nid={0@lo\ $client_nids}\&opcode={ost_read}\ rate=10"

	nrs_write_read
	tbf_verify 20 10

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_w" \
			ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_r" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext\ nid={0@lo\ $client_nids}\&jobid={dd.$RUNAS_ID}\ rate=20"

	nrs_write_read "$RUNAS"
	tbf_verify 20 20 "$RUNAS"

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ ext" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_a\ jobid={dd.$RUNAS_ID},opcode={ost_write}\ rate=20" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_b\ jobid={dd.$RUNAS_ID},opcode={ost_read}\ rate=10"

	nrs_write_read "$RUNAS"
	# with parameter "RUNAS", it will match the latest rule
	# "ext_b" first, so the limited write rate is 10.
	tbf_verify 10 10 "$RUNAS"
	tbf_verify 20 10

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_a" \
			ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_b" \
			ost.OSS.ost_io.nrs_policies="fifo"

	sleep 3
}
run_test 77k "check the extended TBF policy with NID/JobID/OPCode expression"

test_77l() {
	if [ $(lustre_version_code ost1) -lt $(version_code 2.9.54) ]; then
		skip "Need OST version at least 2.9.54"
		return 0
	fi

	local dir=$DIR/$tdir

	mkdir $dir || error "mkdir $dir failed"
	$LFS setstripe -c $OSTCOUNT $dir || error "setstripe to $dir failed"
	chmod 777 $dir

	local nodes=$(comma_list $(osts_nodes))
	do_nodes $nodes lctl set_param ost.OSS.ost_io.nrs_policies=delay \
				       ost.OSS.ost_io.nrs_delay_min=4 \
				       ost.OSS.ost_io.nrs_delay_max=4 \
				       ost.OSS.ost_io.nrs_delay_pct=100
	[ $? -ne 0 ] && error "Failed to set delay policy"

	local start=$SECONDS
	do_nodes "${SINGLECLIENT:-$HOSTNAME}" "$RUNAS" \
		 dd if=/dev/zero of="$dir/nrs_delay_$HOSTNAME" bs=1M count=1 \
		   oflag=direct conv=fdatasync ||
		{ do_nodes $nodes lctl set_param ost.OSS.ost_io.nrs_policies="fifo";
		  error "dd on client failed (1)"; }
	local elapsed=$((SECONDS - start))

	# NRS delay doesn't do sub-second timing, so a request enqueued at
	# 0.9 seconds can be dequeued at 4.0
	[ $elapsed -lt 3 ] &&
		{ do_nodes $nodes lctl set_param ost.OSS.ost_io.nrs_policies="fifo";
		  error "Single 1M write should take at least 3 seconds"; }

	start=$SECONDS
	do_nodes "${SINGLECLIENT:-$HOSTNAME}" "$RUNAS" \
		 dd if=/dev/zero of="$dir/nrs_delay_$HOSTNAME" bs=1M count=10 \
		   oflag=direct conv=fdatasync ||
		{ do_nodes $nodes lctl set_param ost.OSS.ost_io.nrs_policies="fifo";
		  error "dd on client failed (2)"; }
	elapsed=$((SECONDS - start))

	[ $elapsed -lt 30 ] &&
		{ do_nodes $nodes lctl set_param ost.OSS.ost_io.nrs_policies="fifo";
		  error "Ten 1M writes should take at least 30 seconds"; }

	do_nodes $nodes lctl set_param ost.OSS.ost_io.nrs_policies="fifo"
	[ $? -ne 0 ] && error "failed to set policy back to fifo"

	return 0
}
run_test 77l "check NRS Delay slows write RPC processing"

test_78() { #LU-6673
	local server_version=$(lustre_version_code ost1)
	[[ $server_version -ge $(version_code 2.7.58) ]] ||
		{ skip "Need server version newer than 2.7.57"; return 0; }

	local rc

	oss=$(comma_list $(osts_nodes))
	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="orr" &
	do_nodes $oss lctl set_param ost.OSS.*.nrs_orr_quantum=1
	rc=$?
	# Valid return codes are:
	# 0: Tuning succeeded
	# ENODEV: Policy is still stopped
	# EAGAIN: Policy is being initialized
	[ $rc -eq 0 -o $rc -eq 19 -o $rc -eq 11 ] ||
		error "Expected set_param to return 0|ENODEV|EAGAIN"

	# Cleanup the ORR policy
	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="fifo"
	[ $? -ne 0 ] && error "failed to set policy back to fifo"
	return 0
}
run_test 78 "Enable policy and specify tunings right away"

test_79() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	test_mkdir -p $DIR/$tdir

	# Prevent interference from layout intent RPCs due to
	# asynchronous writeback. These will be tested in 130c below.
	do_nodes ${CLIENTS:-$HOSTNAME} sync

	setfattr -n trusted.name1 -v value1 $DIR/$tdir ||
		error "setfattr -n trusted.name1=value1 $DIR/$tdir failed"

#define OBD_FAIL_MDS_INTENT_DELAY		0x160
	local mdtidx=$($LFS getstripe -M $DIR/$tdir)
	local facet=mds$((mdtidx + 1))
	stat $DIR/$tdir
	set_nodes_failloc $(facet_active_host $facet) 0x80000160
	getfattr -n trusted.name1 $DIR/$tdir 2> /dev/null  &
	local pid=$!
	sleep 2

#define OBD_FAIL_MDS_GETXATTR_PACK       0x131
	set_nodes_failloc $(facet_active_host $facet) 0x80000131

	wait $pid
	return 0
}
run_test 79 "xattr: intent error"

test_80a() {
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

	$LFS migrate -m $MDTIDX $DIR1/$tdir &&
		error "migrate open files should failed with open files"

	kill -USR1 $pid

	$LFS migrate -m $MDTIDX $DIR1/$tdir ||
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
run_test 80a "migrate directory when some children is being opened"

cleanup_80b() {
	trap 0
	kill -9 $migrate_pid
}

test_80b() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	local migrate_dir1=$DIR1/$tdir/migrate_dir
	local migrate_dir2=$DIR2/$tdir/migrate_dir
	local migrate_run=$LUSTRE/tests/migrate.sh
	local start_time
	local end_time
	local show_time=1
	local mdt_idx
	local rc=0
	local rc1=0

	trap cleanup_80b EXIT
	#prepare migrate directory
	mkdir -p $migrate_dir1
	for F in {1,2,3,4,5}; do
		echo "$F$F$F$F$F" > $migrate_dir1/file$F
		echo "$F$F$F$F$F" > $DIR/$tdir/file$F
	done

	#migrate the directories among MDTs
	(
		while true; do
			mdt_idx=$((RANDOM % MDSCOUNT))
			$LFS migrate -m $mdt_idx $migrate_dir1 &>/dev/null ||
				rc=$?
			[ $rc -ne 0 -o $rc -ne 16 ] || break
		done
	) &
	migrate_pid=$!

	echo "start migration thread $migrate_pid"
	#Access the files at the same time
	start_time=$(date +%s)
	echo "accessing the migrating directory for 5 minutes..."
	while true; do
		ls $migrate_dir2 > /dev/null || {
			echo "read dir fails"
			break
		}
		diff -u $DIR2/$tdir/file1 $migrate_dir2/file1 || {
			echo "access file1 fails"
			break
		}

		cat $migrate_dir2/file2 > $migrate_dir2/file3 || {
			echo "access file2/3 fails"
			break
		}

		echo "aaaaa" > $migrate_dir2/file4 > /dev/null || {
			echo "access file4 fails"
			break
		}

		stat $migrate_dir2/file5 > /dev/null || {
			echo "stat file5 fails"
			break
		}

		touch $migrate_dir2/source_file > /dev/null || rc1=$?
		[ $rc1 -ne 0 -o $rc1 -ne 1 ] || {
			echo "touch file failed with $rc1"
			break;
		}

		if [ -e $migrate_dir2/source_file ]; then
			ln $migrate_dir2/source_file $migrate_dir2/link_file \
					&>/dev/null || rc1=$?
			if [ -e $migrate_dir2/link_file ]; then
				rm -rf $migrate_dir2/link_file
			fi

			mrename $migrate_dir2/source_file \
				$migrate_dir2/target_file &>/dev/null || rc1=$?
			[ $rc1 -ne 0 -o $rc1 -ne 1 ] || {
				echo "rename failed with $rc1"
				break
			}

			if [ -e $migrate_dir2/target_file ]; then
				rm -rf $migrate_dir2/target_file &>/dev/null ||
								rc1=$?
			else
				rm -rf $migrate_dir2/source_file &>/dev/null ||
								rc1=$?
			fi
			[ $rc1 -ne 0 -o $rc1 -ne 1 ] || {
				echo "unlink failed with $rc1"
				break
			}
		fi

		end_time=$(date +%s)
		duration=$((end_time - start_time))
		if [ $((duration % 10)) -eq 0 ]; then
			if [ $show_time -eq 1 ]; then
				echo "...$duration seconds"
				show_time=0
			fi
		else
			show_time=1
		fi

		kill -0 $migrate_pid || {
			echo "migration stopped 1"
			break
		}

		[ $duration -ge 300 ] && break
	done

	#check migration are still there
	kill -0 $migrate_pid || error "migration stopped 2"
	cleanup_80b
}
run_test 80b "Accessing directory during migration"

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
	mv $DIR2/$tdir/d1/0 $DIR2/$tdir/d0/0 || error "rename d1/0 d0/0 failed"
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
	[[ $(lustre_version_code $SINGLEMDS) -gt $(version_code 2.6.91) ]] ||
		{ skip "Need MDS version at least 2.6.92"; return 0; }

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

test_83() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	local pid1
	local pid2

	(
		cd $DIR1
		while true; do
			$LFS mkdir -i1 -c2 $tdir
			rmdir $tdir
		done
	) &
	pid1=$!
	echo "start pid $pid1 to create/unlink striped directory"

	# Access the directory at the same time
	(
		cd $DIR2
		while true; do
			stat $tdir > /dev/null 2>&1
		done
	) &
	pid2=$!
	echo "start pid $pid2 to stat striped directory"

	sleep 120
	kill $pid1 $pid2
	wait $pid1 $pid2

	return 0
}
run_test 83 "access striped directory while it is being created/unlinked"

test_90() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	local pid1
	local pid2
	local duration=180

	[ "$SLOW" = "yes" ] && duration=600
	# Open/Create under striped directory
	(
		cd $DIR1
		while true; do
			$LFS mkdir -c$MDSCOUNT $tdir > /dev/null 2>&1
			touch $tdir/f{0..3} > /dev/null 2>&1
		done
	) &
	pid1=$!
	echo "start pid $pid1 to open/create under striped directory"

	# unlink the striped directory at the same time
	(
		cd $DIR2
		while true; do
			rm -rf $tdir > /dev/null 2>&1
		done
	) &
	pid2=$!
	echo "start pid $pid2 to unlink striped directory"

	sleep $duration

	kill $pid1 $pid2
	wait $pid1 $pid2

	return 0
}
run_test 90 "open/create and unlink striped directory"

test_91() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	local pid1
	local pid2
	local duration=180

	[ "$SLOW" = "yes" ] && duration=600
	# chmod striped directory
	(
		cd $DIR1
		while true; do
			$LFS mkdir -c$MDSCOUNT $tdir > /dev/null 2>&1
			chmod go+w $tdir > /dev/null 2>&1
		done
	) &
	pid1=$!
	echo "start pid $pid1 to chmod striped directory"

	# unlink the striped directory at the same time
	(
		cd $DIR2
		while true; do
			rm -rf $tdir > /dev/null 2>&1
		done
	) &
	pid2=$!
	echo "start pid $pid2 to unlink striped directory"

	sleep $duration

	kill $pid1 $pid2
	wait $pid1 $pid2

	return 0
}
run_test 91 "chmod and unlink striped directory"

test_92() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	local fd=$(free_fd)
	local cmd="exec $fd<$DIR1/$tdir"
	$LFS setdirstripe -c$MDSCOUNT $DIR1/$tdir || error "mkdir $tdir fails"
	eval $cmd
	cmd="exec $fd<&-"
	trap "eval $cmd" EXIT
	cd $DIR1/$tdir || error "cd $DIR1/$tdir fails"
	rmdir ../$tdir || error "rmdir ../$tdir fails"

	#define OBD_FAIL_LLITE_NO_CHECK_DEAD  0x1408
	$LCTL set_param fail_loc=0x1408
	mkdir $DIR2/$tdir/dir && error "create dir succeeds"
	$LFS setdirstripe -i1 $DIR2/$tdir/remote_dir &&
		error "create remote dir succeeds"
	$LCTL set_param fail_loc=0
	eval $cmd
	return 0
}
run_test 92 "create remote directory under orphan directory"

test_93() {
	local rc1=0
	local rc2=0
	local old_rr

	mkdir -p $DIR1/$tfile-1/
	mkdir -p $DIR2/$tfile-2/
	local old_rr=$(do_facet $SINGLEMDS lctl get_param -n \
		'lod.lustre-MDT*/qos_threshold_rr' | sed -e 's/%//')
	do_facet $SINGLEMDS lctl set_param -n \
		'lod.lustre-MDT*/qos_threshold_rr' 100
	#define OBD_FAIL_MDS_LOV_CREATE_RACE     0x163
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x00000163"

	$SETSTRIPE -c -1 $DIR1/$tfile-1/file1 &
	local PID1=$!
	sleep 1
	$SETSTRIPE -c -1 $DIR2/$tfile-2/file2 &
	local PID2=$!
	wait $PID2
	wait $PID1
	do_facet $SINGLEMDS "lctl set_param fail_loc=0x0"
	do_facet $SINGLEMDS "lctl set_param -n \
		'lod.lustre-MDT*/qos_threshold_rr' $old_rr"

	$GETSTRIPE $DIR1/$tfile-1/file1
	rc1=$($GETSTRIPE -q $DIR1/$tfile-1/file1 |
		awk '{if (/[0-9]/) print $1 }' | sort | uniq -d | wc -l)
	$GETSTRIPE $DIR2/$tfile-2/file2
	rc2=$($GETSTRIPE -q $DIR2/$tfile-2/file2 |
		awk '{if (/[0-9]/) print $1 }' | sort | uniq -d | wc -l)
	echo "rc1=$rc1 and rc2=$rc2 "
	[ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] ||
		error "object allocate on same ost detected"
}
run_test 93 "alloc_rr should not allocate on same ost"

log "cleanup: ======================================================"

# kill and wait in each test only guarentee script finish, but command in script
# like 'rm' 'chmod' may still be running, wait for all commands to finish
# otherwise umount below will fail
[ "$(mount | grep $MOUNT2)" ] && wait_update $HOSTNAME "fuser -m $MOUNT2" "" ||
	true

complete $SECONDS
rm -f $SAMPLE_FILE
check_and_cleanup_lustre
exit_status
