#!/bin/bash

set -e

ONLY=${ONLY:-"$*"}

SIZE=${SIZE:-40960}
OPENFILE=${OPENFILE:-openfile}
OPENUNLINK=${OPENUNLINK:-openunlink}
export TMP=${TMP:-/tmp}
MOUNT_2=${MOUNT_2:-"yes"}
CHECK_GRANT=${CHECK_GRANT:-"yes"}
GRANT_CHECK_LIST=${GRANT_CHECK_LIST:-""}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

ALWAYS_EXCEPT="$SANITYN_EXCEPT "
# bug number for skipped test:  LU-7105
ALWAYS_EXCEPT+="                28 "
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# skip tests for PPC until they are fixed
if [[ $(uname -m) = ppc64 ]]; then
	# bug number:    LU-11597 LU-11787
	ALWAYS_EXCEPT+=" 16a      71a"
fi

if [ $mds1_FSTYPE = "zfs" ]; then
	# LU-2829 / LU-2887 - make allowances for ZFS slowness
	TEST33_NFILES=${TEST33_NFILES:-1000}
fi

#                                  23   (min)"
[ "$SLOW" = "no" ] && EXCEPT_SLOW="33a"

build_test_filter

FAIL_ON_ERROR=false

SETUP=${SETUP:-:}
TRACE=${TRACE:-""}

check_and_setup_lustre

OSC=${OSC:-"osc"}

assert_DIR
rm -rf $DIR1/[df][0-9]* $DIR1/lnk $DIR/[df].${TESTSUITE}*

SAMPLE_FILE=$TMP/$(basename $0 .sh).junk
dd if=/dev/urandom of=$SAMPLE_FILE bs=1M count=1

# $RUNAS_ID may get set incorrectly somewhere else
[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] && error "\$RUNAS_ID set to 0, but \$UID is also 0!"

check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

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
	$CHECKSTAT -t file -p 0777 $DIR1/f2a ||
		error "Either not file type or perms not 0777"
}
run_test 2a "check cached attribute updates on 2 mtpt's ========"

test_2b() {
	touch $DIR1/f2b
	ls -l $DIR2/f2b
	chmod 777 $DIR1/f2b
	$CHECKSTAT -t file -p 0777 $DIR2/f2b ||
		error "Either not file type or perms not 0777"
}
run_test 2b "check cached attribute updates on 2 mtpt's ========"

# NEED TO SAVE ROOT DIR MODE
test_2c() {
	chmod 777 $DIR1
	$CHECKSTAT -t dir -p 0777 $DIR2 ||
		error "Either not dir type or perms not 0777"
}
run_test 2c "check cached attribute updates on 2 mtpt's root ==="

test_2d() {
	chmod 755 $DIR1
	$CHECKSTAT -t dir -p 0755 $DIR2 ||
		error "Either not file type or perms not 0775"
}
run_test 2d "check cached attribute updates on 2 mtpt's root ==="

test_2e() {
        chmod 755 $DIR1
        ls -l $DIR1
        ls -l $DIR2
        chmod 777 $DIR1
		$RUNAS dd if=/dev/zero of=$DIR2/$tfile count=1 ||
			error "dd failed"
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
	[ $block1 -eq $block2 ] || error "$block1 not equal to $block2"
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
	$CHECKSTAT -t file -s 100 $DIR1/f5 ||
		error "Either not file type or size not equal to 100 bytes"
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

test_9a() {
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
run_test 9a "append of file with sub-page size on multiple mounts"

#LU-10681 - tiny writes & appending to sparse striped file
test_9b() {
	[[ $OSTCOUNT -ge 2 ]] || { skip "needs >= 2 OSTs"; return; }

	$LFS setstripe -c 2 -S 1M $DIR/$tfile
	echo "foo" >> $DIR/$tfile
	dd if=/dev/zero of=$DIR2/$tfile bs=1M count=1 seek=1 conv=notrunc ||
		error "sparse dd $DIR2/$tfile failed"
	echo "foo" >> $DIR/$tfile

	data=$(dd if=$DIR2/$tfile bs=1 count=3 skip=$((2 * 1048576)) conv=notrunc)
	echo "Data read (expecting 'foo')": $data
	[ "$data" = "foo" ] || error "append to sparse striped file failed"
}
run_test 9b "append to striped sparse file"

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
	wait $MULTIPID || error "wait for PID $MULTIPID failed"
	[ $RC -eq 0 ] && error || true
}
run_test 11 "execution of file opened for write should return error ===="

test_12() {
	DIR=$DIR DIR2=$DIR2 sh lockorder.sh
}
run_test 12 "test lock ordering (link, stat, unlink)"

test_13() {	# bug 2451 - directory coherency
	test_mkdir $DIR1/d13
	cd $DIR1/d13 || error "cd to $DIR1/d13 failed"
	ls
	( touch $DIR1/d13/f13 ) # needs to be a separate shell
	ls
	rm -f $DIR2/d13/f13 || error "Cannot remove $DIR2/d13/f13"
	ls 2>&1 | grep f13 && error "f13 shouldn't return an error (1)" || true
	# need to run it twice
	( touch $DIR1/d13/f13 ) # needs to be a separate shell
	ls
	rm -f $DIR2/d13/f13 || error "Cannot remove $DIR2/d13/f13"
	ls 2>&1 | grep f13 && error "f13 shouldn't return an error (2)" || true
}
run_test 13 "test directory page revocation"

test_14aa() {
	test_mkdir $DIR1/$tdir
	cp -p /bin/ls $DIR1/$tdir/$tfile
	multiop_bg_pause $DIR1/$tdir/$tfile Ow_c || return 1
	MULTIPID=$!

	$DIR2/$tdir/$tfile && error || true
	kill $MULTIPID
}
run_test 14aa "execution of file open for write returns -ETXTBSY"

test_14ab() {
	test_mkdir $DIR1/$tdir
	cp -p $(which sleep) $DIR1/$tdir/sleep || error "cp failed"
	$DIR1/$tdir/sleep 60 &
	SLEEP_PID=$!
	$MULTIOP $DIR2/$tdir/sleep Oc && error "expected error, got success"
	kill $SLEEP_PID
}
run_test 14ab "open(RDWR) of executing file returns -ETXTBSY"

test_14b() { # bug 3192, 7040
	test_mkdir $DIR1/$tdir
	cp -p $(which sleep) $DIR1/$tdir/sleep || error "cp failed"
	$DIR1/$tdir/sleep 60 &
	SLEEP_PID=$!
	$TRUNCATE $DIR2/$tdir/sleep 60 && kill -9 $SLEEP_PID && \
		error "expected truncate error, got success"
	kill $SLEEP_PID
	cmp $(which sleep) $DIR1/$tdir/sleep || error "binary changed"
}
run_test 14b "truncate of executing file returns -ETXTBSY ======"

test_14c() { # bug 3430, 7040
	test_mkdir $DIR1/$tdir
	cp -p $(which sleep) $DIR1/$tdir/sleep || error "cp failed"
	$DIR1/$tdir/sleep 60 &
	SLEEP_PID=$!
	cp /etc/hosts $DIR2/$tdir/sleep && error "expected error, got success"
	kill $SLEEP_PID
	cmp $(which sleep) $DIR1/$tdir/sleep || error "binary changed"
}
run_test 14c "open(O_TRUNC) of executing file return -ETXTBSY =="

test_14d() { # bug 10921
	test_mkdir $DIR1/$tdir
	cp -p $(which sleep) $DIR1/$tdir/sleep || error "cp failed"
	$DIR1/$tdir/sleep 60 &
	SLEEP_PID=$!
	log chmod
	chmod 600 $DIR1/$tdir/sleep || error "chmod failed"
	kill $SLEEP_PID
	cmp $(which sleep) $DIR1/$tdir/sleep || error "binary changed"
}
run_test 14d "chmod of executing file is still possible ========"

test_15() {	# bug 974 - ENOSPC
	echo "PATH=$PATH"
	sh oos2.sh $MOUNT1 $MOUNT2
	wait_delete_completed
	grant_error=$(dmesg | grep "< tot_grant")
	[ -z "$grant_error" ] || error "$grant_error"
}
run_test 15 "test out-of-space with multiple writers ==========="

COUNT=${COUNT:-2500}
# The FSXNUM reduction for ZFS is needed until ORI-487 is fixed.
# We don't want to skip it entirely, but ZFS is VERY slow and cannot
# pass a 2500 operation dual-mount run within the time limit.
if [ "$ost1_FSTYPE" = "zfs" ]; then
	FSXNUM=$((COUNT / 5))
	FSXP=1
elif [ "$SLOW" = "yes" ]; then
	FSXNUM=$((COUNT * 5))
	FSXP=500
else
	FSXNUM=$COUNT
	FSXP=100
fi

test_16a() {
	local file1=$DIR1/$tfile
	local file2=$DIR2/$tfile
	local stripe_size=$(do_facet $SINGLEMDS \
		"$LCTL get_param -n lod.$(facet_svc $SINGLEMDS)*.stripesize")

	check_set_fallocate

	# to allocate grant because it may run out due to test_15.
	$LFS setstripe -c -1 $file1
	dd if=/dev/zero of=$file1 bs=$stripe_size count=$OSTCOUNT oflag=sync
	dd if=/dev/zero of=$file2 bs=$stripe_size count=$OSTCOUNT oflag=sync
	rm -f $file1

	$LFS setstripe -c -1 $file1 # b=10919
	$FSX -c 50 -p $FSXP -N $FSXNUM -l $((SIZE * 256)) -S 0 $file1 $file2 ||
		error "fsx failed"
	rm -f $file1

	# O_DIRECT reads and writes must be aligned to the device block size.
	$FSX -c 50 -p $FSXP -N $FSXNUM -l $((SIZE * 256)) -S 0 -Z -r 4096 \
		-w 4096 $file1 $file2 || error "fsx with O_DIRECT failed."
}
run_test 16a "$FSXNUM iterations of dual-mount fsx"

# Consistency check for tiny writes, LU-9409
test_16b() {
	local file1=$DIR1/$tfile
	local file2=$DIR2/$tfile
	local stripe_size=($($LFS getstripe -S $DIR))

	check_set_fallocate

	# to allocate grant because it may run out due to test_15.
	lfs setstripe -c -1 $file1
	dd if=/dev/zero of=$file1 bs=$stripe_size count=$OSTCOUNT oflag=sync ||
		error "dd failed writing to file=$file1"
	dd if=/dev/zero of=$file2 bs=$stripe_size count=$OSTCOUNT oflag=sync ||
		error "dd failed writing to file=$file2"
	rm -f $file1

	lfs setstripe -c -1 $file1 # b=10919
	# -o is set to 8192 because writes < 1 page and between 1 and 2 pages
	# create a mix of tiny writes & normal writes
	$FSX -c 50 -p $FSXP -N $FSXNUM -l $((SIZE * 256)) -o 8192 -S 0 \
		$file1 $file2 || error "fsx with tiny write failed."
}
run_test 16b "$FSXNUM iterations of dual-mount fsx at small size"

test_16c() {
	local file1=$DIR1/$tfile
	local file2=$DIR2/$tfile
	local stripe_size=$(do_facet $SINGLEMDS \
		"$LCTL get_param -n lod.$(facet_svc $SINGLEMDS)*.stripesize")

	[ "$ost1_FSTYPE" != ldiskfs ] && skip "dio on ldiskfs only"

	check_set_fallocate

	# to allocate grant because it may run out due to test_15.
	$LFS setstripe -c -1 $file1
	dd if=/dev/zero of=$file1 bs=$stripe_size count=$OSTCOUNT oflag=sync
	dd if=/dev/zero of=$file2 bs=$stripe_size count=$OSTCOUNT oflag=sync
	rm -f $file1
	wait_delete_completed

	local list=$(comma_list $(osts_nodes))
	if ! get_osd_param $list '' read_cache_enable >/dev/null; then
		skip "not cache-capable obdfilter"
	fi

	set_osd_param $list '' read_cache_enable 0
	set_osd_param $list '' writethrough_cache_enable 0

	$LFS setstripe -c -1 $file1 # b=10919
	$FSX -c 50 -p $FSXP -N $FSXNUM -l $((SIZE * 256)) -S 0 $file1 $file2 ||
		error "fsx failed"
	rm -f $file1

	set_osd_param $list '' read_cache_enable 1
	set_osd_param $list '' writethrough_cache_enable 1

	return 0
}
run_test 16c "verify data consistency on ldiskfs with cache disabled (b=17397)"

test_16d() {
	local file1=$DIR1/$tfile
	local file2=$DIR2/$tfile
	local file3=$DIR1/file
	local tmpfile=$(mktemp)
	local stripe_size=$(do_facet $SINGLEMDS \
		"$LCTL get_param -n lod.$(facet_svc $SINGLEMDS)*.stripesize")

	# to allocate grant because it may run out due to test_15.
	$LFS setstripe -c -1 $file1
	stack_trap "rm -f $file1 $file2 $file3 $tmpfile"
	dd if=/dev/zero of=$file1 bs=$stripe_size count=$OSTCOUNT oflag=sync
	dd if=/dev/zero of=$file2 bs=$stripe_size count=$OSTCOUNT oflag=sync
	rm -f $file1

	$LFS setstripe -c -1 $file1 # b=10919
	$LCTL set_param ldlm.namespaces.*.lru_size=clear
	
	# direct write on one client and direct read from another
	dd if=/dev/urandom of=$file1 bs=1M count=100 oflag=direct
	dd if=$file2 of=$tmpfile iflag=direct bs=1M
	diff $file1 $tmpfile || error "file different(1)"
	rm -f $file1

	# buffer write on one client, but direct read from another
	dd if=$tmpfile of=$file1 bs=1M count=100
	dd if=$file2 of=$file3 bs=1M iflag=direct count=100
	diff $file3 $tmpfile || error "file different(2)"

	rm -f $file3 $file2 $file1
	# direct write on one client
	dd if=$tmpfile of=$file1 bs=1M count=100 oflag=direct
	# buffer read from another client
	dd if=$file2 of=$file3 bs=1M count=100
	diff $file3 $tmpfile || error "file different(3)"
}
run_test 16d "Verify DIO and buffer IO with two clients"

test_16e() { # LU-13227
	# issue:	LU-14314

	(( "$MDS1_VERSION" >= $(version_code 2.13.53) )) ||
		skip "Need MDS version at least 2.13.53"

	local file1=$DIR1/$tfile
	local file2=$DIR2/$tfile

	# client1 write 10M data
	dd if=/dev/zero of=$file1 bs=1M count=10
	# drop locks
	cancel_lru_locks osc > /dev/null
	# use lockahead to generate one PW lock to keep LVB loaded.
	$LFS ladvise -a lockahead --start 0 --length 1M \
		--mode WRITE $file1
	# direct write to extend file size on client2
	dd if=/dev/zero of=$file2 bs=1M seek=20 count=1 \
		oflag=direct conv=notrunc
	local filesize=$(stat -c %s $file2)
	[ "$filesize" -eq 22020096 ] ||
		error "expected filesize 22020096 got $filesize"
	rm -f $file1
}
run_test 16e "Verify size consistency for O_DIRECT write"

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

	excepts="$excepts -e 7 -e 8 -e 9"
	$LUSTRE/tests/mmap_sanity -d $MOUNT1 -m $MOUNT2 $excepts ||
		error "mmap_sanity test failed"
	sync; sleep 1; sync
}
run_test 18 "mmap sanity check ================================="

test_19() { # bug3811
	local node=$(facet_active_host ost1)
	local device="$FSNAME-OST*"

	[ "x$DOM" = "xyes" ] && node=$(facet_active_host $SINGLEMDS) &&
		device="$FSNAME-MDT*"

	# check whether obdfilter is cache capable at all
	get_osd_param $node $device read_cache_enable >/dev/null ||
		skip "not cache-capable obdfilter"

	local max=$(get_osd_param $node $device readcache_max_filesize |\
		head -n 1)
	set_osd_param $node $device readcache_max_filesize 4096
	dd if=/dev/urandom of=$TMP/$tfile bs=512k count=32
	local SUM=$(cksum $TMP/$tfile | cut -d" " -f 1,2)
	cp $TMP/$tfile $DIR1/$tfile
	for i in `seq 1 20`; do
		[ $((i % 5)) -eq 0 ] && log "$testname loop $i"
		cancel_lru_locks $OSC > /dev/null
		cksum $DIR1/$tfile | cut -d" " -f 1,2 > $TMP/sum1 & \
		cksum $DIR2/$tfile | cut -d" " -f 1,2 > $TMP/sum2
		wait
		[ "$(cat $TMP/sum1)" = "$SUM" ] || \
			error "$DIR1/$tfile $(cat $TMP/sum1) != $SUM"
		[ "$(cat $TMP/sum2)" = "$SUM" ] || \
			error "$DIR2/$tfile $(cat $TMP/sum2) != $SUM"
	done
	set_osd_param $node $device readcache_max_filesize $max
	rm $DIR1/$tfile
}
run_test 19 "test concurrent uncached read races ==============="

test_20() {
	test_mkdir $DIR1/$tdir
	cancel_lru_locks
	CNT=$($LCTL get_param -n llite.*.dump_page_cache | wc -l)
	$MULTIOP $DIR1/$tdir/$tfile Ow8190c
	$MULTIOP $DIR2/$tdir/$tfile Oz8194w8190c
	$MULTIOP $DIR1/$tdir/$tfile Oz0r8190c
	cancel_lru_locks
	CNT2=$($LCTL get_param -n llite.*.dump_page_cache | wc -l)
	[[ $CNT2 == $CNT ]] ||
		error $((CNT2 - CNT))" page left in cache after lock cancel"
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
	cancel_lru_locks $OSC
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
	lctl --device %osc deactivate
	lfs df -i || error "lfs df -i with deactivated OSC failed"
	lctl --device %osc activate
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
	utime $DIR1/f26a -s $DIR2/f26a || error "utime failed for $DIR1/f26a"
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
	cancel_lru_locks $OSC
	lctl clear
	dd if=/dev/zero of=$DIR2/$tfile bs=$((4096+4))k conv=notrunc count=4 seek=3 &
	DD2_PID=$!
	sleep 0.5
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
	dd if=$DIR2/$tfile of=/dev/null bs=1024k count=1 || error "dd failed"
	# reading of 2nd stripe should fail (this stripe was destroyed)
	dd if=$DIR2/$tfile of=/dev/null bs=1024k count=1 skip=1 && error

	# now, recreating test file
	dd if=/dev/zero of=$DIR1/$tfile bs=1024k count=2 || error "dd failed"
	# reading of 1st stripe should pass
	dd if=$DIR2/$tfile of=/dev/null bs=1024k count=1 || error "dd failed"
	# reading of 2nd stripe should pass
	dd if=$DIR2/$tfile of=/dev/null bs=1024k count=1 skip=1 ||
		error "dd failed"
}
run_test 28 "read/write/truncate file with lost stripes"

test_30() { #b=11110, LU-2523
	test_mkdir $DIR1/$tdir
	cp -f /bin/bash $DIR1/$tdir/bash
	/bin/sh -c 'sleep 1; rm -f $DIR2/$tdir/bash; cp /bin/bash $DIR2/$tdir' &
	$DIR1/$tdir/bash -c 'sleep 2;
		openfile -f O_RDONLY /proc/$$/exe >& /dev/null; echo $?'
	wait
	true
}
run_test 30 "recreate file race"

test_31a() {
	test_mkdir $DIR1/$tdir
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

	test_mkdir $DIR1/$tdir
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

#LU-14949 - multi-client version of the test 31r in sanity.
test_31r() {
	touch $DIR/$tfile.target
	touch $DIR/$tfile.source

	ls -l $DIR/$tfile.target # cache it for sure

	#OBD_FAIL_LLITE_OPEN_DELAY 0x1419
	$LCTL set_param fail_loc=0x1419 fail_val=3
	cat $DIR/$tfile.target &
	CATPID=$!

	# Guarantee open is waiting before we get here
	sleep 1
	mv $DIR2/$tfile.source $DIR2/$tfile.target

	wait $CATPID
	RC=$?
	if [[ $RC -ne 0 ]]; then
		error "open with cat failed, rc=$RC"
	fi
}
run_test 31r "open-rename(replace) race"

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
	clear_stats $OSC.*.${OSC}_stats

	# agressive lockless i/o settings
	do_nodes $(comma_list $(osts_nodes)) \
		"lctl set_param -n ldlm.namespaces.*.max_nolock_bytes=2000000 \
			ldlm.namespaces.filter-*.contended_locks=0 \
			ldlm.namespaces.filter-*.contention_seconds=60"
	lctl set_param -n $OSC.*.contention_seconds=60
	for i in {1..5}; do
		dd if=/dev/zero of=$DIR1/$tfile bs=4k count=1 conv=notrunc > \
			/dev/null 2>&1
		dd if=/dev/zero of=$DIR2/$tfile bs=4k count=1 conv=notrunc > \
			/dev/null 2>&1
	done
	[ $(calc_stats $OSC.*.${OSC}_stats lockless_write_bytes) -ne 0 ] ||
		error "lockless i/o was not triggered"
	# disable lockless i/o (it is disabled by default)
	do_nodes $(comma_list $(osts_nodes)) \
		"lctl set_param -n ldlm.namespaces.filter-*.max_nolock_bytes=0 \
			ldlm.namespaces.filter-*.contended_locks=32 \
			ldlm.namespaces.filter-*.contention_seconds=0"
	# set contention_seconds to 0 at client too, otherwise Lustre still
	# remembers lock contention
	lctl set_param -n $OSC.*.contention_seconds=0
	clear_stats $OSC.*.${OSC}_stats
	for i in {1..1}; do
		dd if=/dev/zero of=$DIR1/$tfile bs=4k count=1 conv=notrunc > \
			/dev/null 2>&1
		dd if=/dev/zero of=$DIR2/$tfile bs=4k count=1 conv=notrunc > \
			/dev/null 2>&1
	done
	[ $(calc_stats $OSC.*.${OSC}_stats lockless_write_bytes) -eq 0 ] ||
		error "lockless i/o works when disabled"
	rm -f $DIR1/$tfile
	restore_lustre_params <$p
	rm -f $p
}
# Disable test 32b prior to full removal
#run_test 32b "lockless i/o"

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

	[ -z "$CLIENTS" ] && skip "Need two or more clients, have $CLIENTS"
	[ $CLIENTCOUNT -lt 2 ] &&
		skip "Need two or more clients, have $CLIENTCOUNT"

	local nfiles=${TEST33_NFILES:-10000}
	local param_file=$TMP/$tfile-params
	local COS
	local jbdold="N/A"
	local jbdnew="N/A"
	local jbd

	save_lustre_params $(get_facets MDS) \
		"mdt.*.commit_on_sharing" > $param_file

	for COS in 0 1; do
		do_facet $SINGLEMDS lctl set_param mdt.*.commit_on_sharing=$COS
		avgjbd=0
		avgtime=0
		for i in 1 2 3; do
			do_nodes $CLIENT1,$CLIENT2 "mkdir -p $DIR1/$tdir-\\\$(hostname)-$i"

		[ "$mds1_FSTYPE" = ldiskfs ] && jbdold=$(print_jbd_stat)
		echo "=== START createmany old: $jbdold transaction"
		local elapsed=$(do_and_time "do_nodes $CLIENT1,$CLIENT2 createmany -o $DIR1/$tdir-\\\$(hostname)-$i/f- -r$DIR2/$tdir-\\\$(hostname)-$i/f- $nfiles > /dev/null 2>&1")
		[ "$mds1_FSTYPE" = ldiskfs ] && jbdnew=$(print_jbd_stat)
		[ "$mds1_FSTYPE" = ldiskfs ] && jbd=$(( jbdnew - jbdold ))
		echo "=== END   createmany new: $jbdnew transaction :  $jbd transactions  nfiles $nfiles time $elapsed COS=$COS"
		[ "$mds1_FSTYPE" = ldiskfs ] && avgjbd=$(( avgjbd + jbd ))
		avgtime=$(( avgtime + elapsed ))
		done
	eval cos${COS}_jbd=$((avgjbd / 3))
	eval cos${COS}_time=$((avgtime / 3))
	done

	echo "COS=0 transactions (avg): $cos0_jbd  time (avg): $cos0_time"
	echo "COS=1 transactions (avg): $cos1_jbd  time (avg): $cos1_time"
	[ "$cos0_jbd" != 0 ] &&
		echo "COS=1 vs COS=0 jbd:  $((((cos1_jbd/cos0_jbd - 1)) * 100 )) %"
	[ "$cos0_time" != 0 ] &&
		echo "COS=1 vs COS=0 time: $((((cos1_time/cos0_time - 1)) * 100 )) %"

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
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	[ "$MDS1_VERSION" -lt $(version_code 2.7.63) ] &&
		skip "DNE CoS not supported"

	# LU-13522
	stop mds1
	start mds1 $(mdsdevname 1) $MDS_MOUNT_OPTS || error "start mds1 failed"

	local sync_count

	mkdir_on_mdt0 $DIR/$tdir
	sync_all_data
	do_facet mds1 "lctl set_param -n mdt.*.sync_count=0"
	# do twice in case transaction is committed before unlock, see LU-8200
	for i in 1 2; do
		# remote dir is created on MDT1, which enqueued lock of $tdir on
		# MDT0
		$LFS mkdir -i 1 $DIR/$tdir/remote.$i
		mkdir $DIR/$tdir/local.$i
	done
	sync_count=$(do_facet mds1 "lctl get_param -n mdt.*MDT0000.sync_count")
	echo "sync_count $sync_count"
	[ $sync_count -eq 0 ] && error "Sync-Lock-Cancel not triggered"

	sync_all_data
	do_facet mds1 "lctl set_param -n mdt.*.sync_count=0"
	$LFS mkdir -i 1 $DIR/$tdir/remote.3
	# during sleep remote mkdir should have been committed and canceled
	# remote lock spontaneously, which shouldn't trigger sync
	sleep 6
	mkdir $DIR/$tdir/local.3
	sync_count=$(do_facet mds1 "lctl get_param -n mdt.*MDT0000.sync_count")
	echo "sync_count $sync_count"
	[ $sync_count -eq 0 ] || error "Sync-Lock-Cancel triggered"
}
run_test 33c "Cancel cross-MDT lock should trigger Sync-Lock-Cancel"

# arg1 is operations done before CoS, arg2 is the operation that triggers CoS
op_trigger_cos() {
	local commit_nr
	local total=0
	local nodes=$(comma_list $(mdts_nodes))

	sync_all_data

	# trigger CoS twice in case transaction commit before unlock
	for i in 1 2; do
		sh -c "$1"
		do_nodes $nodes "lctl set_param -n mdt.*.async_commit_count=0"
		sh -c "$2"
		commit_nr=$(do_nodes $nodes \
			"lctl get_param -n mdt.*.async_commit_count" | calc_sum)
		total=$((total + commit_nr));
		rm -rf $DIR/$tdir
		sync_all_data
	done

	echo "CoS count $total"
	[ $total -gt 0 ] || error "$2 didn't trigger CoS"
}

test_33d() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	[ "$MDS1_VERSION" -lt $(version_code 2.7.63) ] &&
		skip "DNE CoS not supported"

	# remote directory create
	op_trigger_cos "$LFS mkdir -i 0 $DIR/$tdir" "$LFS mkdir -i 1 $DIR/$tdir/subdir"
	# remote directory unlink
	op_trigger_cos "$LFS mkdir -i 1 $DIR/$tdir" "rmdir $DIR/$tdir"
	# striped directory create
	op_trigger_cos "mkdir $DIR/$tdir" "$LFS mkdir -c 2 $DIR/$tdir/subdir"
	# striped directory setattr
	op_trigger_cos "$LFS mkdir -c 2 $DIR/$tdir; touch $DIR/$tdir" \
		"chmod 713 $DIR/$tdir"
	# striped directory unlink
	op_trigger_cos "$LFS mkdir -c 2 $DIR/$tdir; touch $DIR/$tdir" \
		"rmdir $DIR/$tdir"
	# cross-MDT link
	op_trigger_cos "$LFS mkdir -c 2 $DIR/$tdir; \
			$LFS mkdir -i 0 $DIR/$tdir/d1; \
			$LFS mkdir -i 1 $DIR/$tdir/d2; \
			touch $DIR/$tdir/d1/tgt" \
		"ln $DIR/$tdir/d1/tgt $DIR/$tdir/d2/src"
	# cross-MDT rename
	op_trigger_cos "$LFS mkdir -c 2 $DIR/$tdir; \
			$LFS mkdir -i 0 $DIR/$tdir/d1; \
			$LFS mkdir -i 1 $DIR/$tdir/d2; \
			touch $DIR/$tdir/d1/src" \
		"mv $DIR/$tdir/d1/src $DIR/$tdir/d2/tgt"
	# migrate
	op_trigger_cos "$LFS mkdir -i 0 $DIR/$tdir" \
		"$LFS migrate -m 1 $DIR/$tdir"

	return 0
}
run_test 33d "DNE distributed operation should trigger COS"

test_33e() {
	[ -n "$CLIENTS" ] || skip "Need two or more clients"
	[ $CLIENTCOUNT -ge 2 ] ||
		skip "Need two or more clients, have $CLIENTCOUNT"
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs"
	[ "$MDS1_VERSION" -lt $(version_code 2.7.63) ] &&
		skip "DNE CoS not supported"

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
		wait_osc_import_ready client ost$i
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

	test_mkdir $MOUNT1/$tdir
	cancel_lru_locks mdc

	# Let's initiate -EINTR situation by setting fail_loc and take
	# write lock on same file from same client. This will not cause
	# bl_ast yet as lock is already in local cache.
	#define OBD_FAIL_LDLM_INTR_CP_AST        0x317
	do_facet client "lctl set_param fail_loc=0x80000317"
	local timeout=$(do_facet $SINGLEMDS lctl get_param  -n timeout)
	let timeout=timeout*3
	local nr=0
	while test $nr -lt 10; do
		log "Race attempt $nr"
		local blk1=$(lctl get_param -n ldlm.services.ldlm_cbd.stats |
			     awk '/ldlm_bl_callback/ { print $2 }')
		test "x$blk1" = "x" && blk1=0
		createmany -o $MOUNT2/$tdir/a 4000 &
		pid1=$!
		sleep 1

		# Let's make conflict and bl_ast
		ls -la $MOUNT1/$tdir > /dev/null &
		pid2=$!

		log "Wait for $pid1 $pid2 for $timeout sec..."
		sleep $timeout
		kill -9 $pid1 $pid2 > /dev/null 2>&1
		wait
		local blk2=$(lctl get_param -n ldlm.services.ldlm_cbd.stats |
			     awk '/ldlm_bl_callback/ { print $2 }')
		test "x$blk2" = "x" && blk2=0
		test $blk2 -gt $blk1 && break
		rm -fr $MOUNT1/$tdir
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
		local c=0
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

	test_mkdir $DIR1/$tdir
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
	test_mkdir $DIR1/$tdir
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

	cancel_lru_locks $OSC

	local mtime2=$(stat -c %Y $DIR2/$tfile)
	[ "$mtime2" -ge "$d1" ] && [ "$mtime2" -le "$d2" ] ||
		error "mtime is not updated on write: $d1 <= $mtime2 <= $d2"
}
run_test 39d "sync write should update mtime"

pdo_sched() {
	# how long 40-47 take with specific delay
	# sleep 0.1 # 78s
	# sleep 0.2 # 103s
	# sleep 0.3 # 124s
	sleep 0.5 # 164s
}

# for pdo testing, we must cancel MDT-MDT locks as well as client locks to
# avoid unexpected delays due to previous tests
pdo_lru_clear() {
	cancel_lru_locks mdc
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL set_param -n ldlm.namespaces.*mdt*.lru_size=clear
	do_nodes $(comma_list $(mdts_nodes)) \
		$LCTL get_param ldlm.namespaces.*mdt*.lock_unused_count \
			ldlm.namespaces.*mdt*.lock_count | grep -v '=0'
}

# check that pid exists hence second operation wasn't blocked by first one
# if it is so then there is no conflict, return 0
# else second operation is conflicting with first one, return 1
check_pdo_conflict() {
	local pid=$1
	local conflict=0
	pdo_sched # to ensure OP1 is finished on client if OP2 is blocked by OP1
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

	mkdir_on_mdt0 $DIR2/$tdir
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mkdir $DIR1/$tdir/$tfile &
	PID1=$!; pdo_sched
	touch $DIR2/$tdir/$tfile-2
	check_pdo_conflict $PID1 || error "create is blocked"
	mkdir $DIR2/$tdir/$tfile-3
	check_pdo_conflict $PID1 || error "mkdir is blocked"
	link $DIR2/$tdir/$tfile-2 $DIR2/$tdir/$tfile-4
	check_pdo_conflict $PID1 || error "link is blocked"
	mv $DIR2/$tdir/$tfile-2 $DIR2/$tdir/$tfile-5
	check_pdo_conflict $PID1 || error "rename is blocked"
	stat $DIR2/$tdir/$tfile-3 $DIR2/$tdir/$tfile-4 > /dev/null
	check_pdo_conflict $PID1 || error "getattr is blocked"
	rm $DIR2/$tdir/$tfile-4 $DIR2/$tdir/$tfile-5
	rmdir $DIR2/$tdir/$tfile-3
	check_pdo_conflict $PID1 || error "unlink is blocked"

	#  all operations above shouldn't wait the first one
	check_pdo_conflict $PID1 || error "parallel operation is blocked"
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	wait $PID1
	rm -rf $DIR/$tdir
	return 0
}
run_test 40a "pdirops: create vs others =============="

test_40b() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return

	mkdir_on_mdt0 $DIR2/$tdir
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	touch $DIR1/$tdir/$tfile &
	PID1=$!; pdo_sched
	# open|create
	touch $DIR2/$tdir/$tfile-2
	check_pdo_conflict $PID1 || error "create is blocked"
	mkdir $DIR2/$tdir/$tfile-3
	check_pdo_conflict $PID1 || error "mkdir is blocked"
	link $DIR2/$tdir/$tfile-2 $DIR2/$tdir/$tfile-4
	check_pdo_conflict $PID1 || error "link is blocked"
	mv $DIR2/$tdir/$tfile-2 $DIR2/$tdir/$tfile-5
	check_pdo_conflict $PID1 || error "rename is blocked"
	stat $DIR2/$tdir/$tfile-3 $DIR2/$tdir/$tfile-4 > /dev/null
	check_pdo_conflict $PID1 || error "getattr is blocked"
	rm $DIR2/$tdir/$tfile-4 $DIR2/$tdir/$tfile-5
	rmdir $DIR2/$tdir/$tfile-3
	check_pdo_conflict $PID1 || error "unlink is blocked"
	# all operations above shouldn't wait the first one

        check_pdo_conflict $PID1 || error "parallel operation is blocked"
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	wait $PID1
	rm -rf $DIR/$tdir
	return 0
}
run_test 40b "pdirops: open|create and others =============="

test_40c() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return

	mkdir_on_mdt0 $DIR2/$tdir
	pdo_lru_clear
	touch $DIR1/$tdir/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	link $DIR1/$tdir/$tfile $DIR1/$tdir/$tfile-0 &
	PID1=$!; pdo_sched
	# open|create
	touch $DIR2/$tdir/$tfile-2
	check_pdo_conflict $PID1 || error "create is blocked"
	mkdir $DIR2/$tdir/$tfile-3
	check_pdo_conflict $PID1 || error "mkdir is blocked"
	link $DIR2/$tdir/$tfile-2 $DIR2/$tdir/$tfile-4
	check_pdo_conflict $PID1 || error "link is blocked"
	mv $DIR2/$tdir/$tfile-2 $DIR2/$tdir/$tfile-5
	check_pdo_conflict $PID1 || error "rename is blocked"
	stat $DIR2/$tdir/$tfile-3 $DIR2/$tdir/$tfile-4 > /dev/null
	check_pdo_conflict $PID1 || error "getattr is blocked"
	rm $DIR2/$tdir/$tfile-4 $DIR2/$tdir/$tfile-5
	rmdir $DIR2/$tdir/$tfile-3
	check_pdo_conflict $PID1 || error "unlink is blocked"

        # all operations above shouldn't wait the first one
	check_pdo_conflict $PID1 || error "parallel operation is blocked"
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	wait $PID1
	rm -rf $DIR/$tdir
	return 0
}
run_test 40c "pdirops: link and others =============="

test_40d() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return

	mkdir_on_mdt0 $DIR2/$tdir
	pdo_lru_clear
	touch $DIR1/$tdir/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	rm $DIR1/$tdir/$tfile &
	PID1=$!; pdo_sched
	# open|create
	touch $DIR2/$tdir/$tfile-2
	check_pdo_conflict $PID1 || error "create is blocked"
	mkdir $DIR2/$tdir/$tfile-3
	check_pdo_conflict $PID1 || error "mkdir is blocked"
	link $DIR2/$tdir/$tfile-2 $DIR2/$tdir/$tfile-4
	check_pdo_conflict $PID1 || error "link is blocked"
	mv $DIR2/$tdir/$tfile-2 $DIR2/$tdir/$tfile-5
	check_pdo_conflict $PID1 || error "rename is blocked"
	stat $DIR2/$tdir/$tfile-3 $DIR2/$tdir/$tfile-4 > /dev/null
	check_pdo_conflict $PID1 || error "getattr is blocked"
	rm $DIR2/$tdir/$tfile-4 $DIR2/$tdir/$tfile-5
	rmdir $DIR2/$tdir/$tfile-3
	check_pdo_conflict $PID1 || error "unlink is blocked"

	# all operations above shouldn't wait the first one
	check_pdo_conflict $PID1 || error "parallel operation is blocked"
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	wait $PID1
	return 0
}
run_test 40d "pdirops: unlink and others =============="

test_40e() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return

	mkdir_on_mdt0 $DIR2/$tdir
	pdo_lru_clear
	touch $DIR1/$tdir/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mv $DIR1/$tdir/$tfile $DIR1/$tdir/$tfile-0 &
	PID1=$!; pdo_sched
	# open|create
	touch $DIR2/$tdir/$tfile-2
	check_pdo_conflict $PID1 || error "create is blocked"
	mkdir $DIR2/$tdir/$tfile-3
	check_pdo_conflict $PID1 || error "mkdir is blocked"
	link $DIR2/$tdir/$tfile-2 $DIR2/$tdir/$tfile-4
	check_pdo_conflict $PID1 || error "link is blocked"
	stat $DIR2/$tdir/$tfile-3 $DIR2/$tdir/$tfile-4 > /dev/null
	check_pdo_conflict $PID1 || error "getattr is blocked"
	rm $DIR2/$tdir/$tfile-4 $DIR2/$tdir/$tfile-2
	rmdir $DIR2/$tdir/$tfile-3
	check_pdo_conflict $PID1 || error "unlink is blocked"

       # all operations above shouldn't wait the first one
	check_pdo_conflict $PID1 || error "parallel operation is blocked"
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	wait $PID1
	rm -rf $DIR/$tdir
	return 0
}
run_test 40e "pdirops: rename and others =============="

# test 41: create blocking operations
test_41a() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$! ; pdo_sched
	mkdir $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; echo "mkdir isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "mkdir must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 41a "pdirops: create vs mkdir =============="

test_41b() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$! ; pdo_sched
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "create must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 41b "pdirops: create vs create =============="

test_41c() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$! ; pdo_sched
	link $DIR2/$tfile-2 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "link must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 41c "pdirops: create vs link =============="

test_41d() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$! ; pdo_sched
	rm $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "unlink must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 41d "pdirops: create vs unlink =============="

test_41e() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile-2 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rename must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 41e "pdirops: create and rename (tgt) =============="

test_41f() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile $DIR2/$tfile-2 &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rename must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 41f "pdirops: create and rename (src) =============="

test_41g() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$! ; pdo_sched
	stat $DIR2/$tfile > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "stat must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 41g "pdirops: create vs getattr =============="

test_41h() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$MULTIOP $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$! ; pdo_sched
	ls -lia $DIR2/ > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	wait $PID2
	rm -rf $DIR/$tfile*
	return 0
}
run_test 41h "pdirops: create vs readdir =============="

sub_test_41i() {
	local PID1 PID2
	local fail_loc="$1"
	local ret=0

	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=${fail_loc} || true" &>/dev/null

	$MULTIOP $DIR1/$tfile oO_CREAT:O_EXCL:c 2>/dev/null &
	PID1=$!
	sleep 0.2
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c 2>/dev/null &
	PID2=$!

	if ! wait $PID1 && ! wait $PID2; then
		echo "Both creates failed (1 should fail, 1 should succeed)"
		ret=1
	elif wait $PID1 && wait $PID2; then
		echo "Both creates succeeded (1 should fail, 1 should succeed)"
		ret=2
	fi

	#Clean
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x0 || true" &>/dev/null
	rm -f $DIR/$tfile

	return $ret
}

test_41i() {
	[[ $MDS1_VERSION -le $(version_code 2.13.56) ]] ||
		skip "Need MDS version newer than 2.13.56"
	local msg fail_loc

#define OBD_FAIL_ONCE|OBD_FAIL_MDS_REINT_OPEN         0x169
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_REINT_OPEN2        0x16a
	for fail_loc in "0x80000169" "0x8000016a"; do
		echo "Begin 100 tests with fail_loc=$fail_loc"
		printf "Progress: "
		for i in {1..100}; do
			printf "*"
			msg=$(sub_test_41i "$fail_loc") ||
				{ echo; error "iter=$i : $msg"; }
		done
		echo
	done
}
run_test 41i "reint_open: create vs create"


# test 42: unlink and blocking operations
test_42a() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mkdir $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mkdir $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "mkdir isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "mkdir must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 42a "pdirops: mkdir vs mkdir =============="

test_42b() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mkdir $DIR1/$tfile &
	PID1=$! ; pdo_sched
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "create must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 42b "pdirops: mkdir vs create =============="

test_42c() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mkdir $DIR1/$tfile &
	PID1=$! ; pdo_sched
	link $DIR2/$tfile-2 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "link must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 42c "pdirops: mkdir vs link =============="

test_42d() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mkdir $DIR1/$tfile &
	PID1=$! ; pdo_sched
	rmdir $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "unlink must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 42d "pdirops: mkdir vs unlink =============="

test_42e() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mkdir $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mv -T $DIR2/$tfile-2 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "rename must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 42e "pdirops: mkdir and rename (tgt) =============="

test_42f() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mkdir $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile $DIR2/$tfile-2 &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rename must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 42f "pdirops: mkdir and rename (src) =============="

test_42g() {
	mkdir_on_mdt0 $DIR1/$tdir
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mkdir $DIR1/$tdir/$tfile &
	PID1=$! ; pdo_sched
	stat $DIR2/$tdir/$tfile > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "stat must succeed"
	rm -rf $DIR/$tdir
}
run_test 42g "pdirops: mkdir vs getattr =============="

test_42h() {
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mkdir $DIR1/$tfile &
	PID1=$! ; pdo_sched
	ls -lia $DIR2/ > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	wait $PID2
	rm -rf $DIR/$tfile*
	return 0
}
run_test 42h "pdirops: mkdir vs readdir =============="

# test 43: rmdir,mkdir won't return -EEXIST
test_43a() {
	for i in {1..1000}; do
		mkdir $DIR1/$tdir || error "mkdir $tdir failed"
		rmdir $DIR2/$tdir || error "rmdir $tdir failed"
	done
	return 0
}
run_test 43a "rmdir,mkdir doesn't return -EEXIST =============="

test_43b() {
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	rm $DIR1/$tfile &
	PID1=$! ; pdo_sched
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "create must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 43b "pdirops: unlink vs create =============="

test_43c() {
	pdo_lru_clear
	touch $DIR1/$tfile
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	rm $DIR1/$tfile &
	PID1=$! ; pdo_sched
	link $DIR2/$tfile-2 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "link must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 43c "pdirops: unlink vs link =============="

test_43d() {
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	rm $DIR1/$tfile &
	PID1=$! ; pdo_sched
	rm $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "unlink must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 43d "pdirops: unlink vs unlink =============="

test_43e() {
	pdo_lru_clear
	touch $DIR1/$tfile
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	rm $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mv -u $DIR2/$tfile-2 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rename must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 43e "pdirops: unlink and rename (tgt) =============="

test_43f() {
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	rm $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile $DIR2/$tfile-2 &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "rename must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 43f "pdirops: unlink and rename (src) =============="

test_43g() {
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	rm $DIR1/$tfile &
	PID1=$! ; pdo_sched
	stat $DIR2/$tfile > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "stat must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 43g "pdirops: unlink vs getattr =============="

test_43h() {
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	rm $DIR1/$tfile &
	PID1=$! ; pdo_sched
	ls -lia $DIR2/ > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	wait $PID2
	rm -rf $DIR/$tfile*
	return 0
}
run_test 43h "pdirops: unlink vs readdir =============="

test_43i() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	rm $DIR1/$tfile &
	PID1=$! ; pdo_sched
	$LFS mkdir -i 1 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 &&
		{ wait $PID1; error "remote mkdir isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "remote mkdir must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 43i "pdirops: unlink vs remote mkdir"

test_43j() {
	[[ $MDS1_VERSION -lt $(version_code 2.13.52) ]] &&
		skip "Need MDS version newer than 2.13.52"

	mkdir_on_mdt0 $DIR1/$tdir
	for i in {1..100}; do
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_CREATE_RACE         0x167
		do_nodes $(comma_list $(mdts_nodes)) \
			"lctl set_param -n fail_loc=0x80000167 2>/dev/null ||
				true"
		OK=0
		mkdir $DIR1/$tdir/sub &
		PID1=$!
		mkdir $DIR2/$tdir/sub && ((OK++))
		wait $PID1 && ((OK++))
		(( OK == 1 )) || error "exactly one mkdir should succeed"

		rmdir $DIR1/$tdir/sub || error "rmdir failed"
	done
	return 0
}
run_test 43j "racy mkdir return EEXIST =============="

sub_test_43k() {
	local PID1 PID2
	local fail_loc="$1"
	local ret=0

	# We test in a separate directory to be able to unblock server thread in
	# cfs_race() if LCK_PW is taken on the parent by mdt_reint_unlink.
	test_mkdir $DIR2/$tdir
	touch $DIR2/$tdir/$tfile

	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=${fail_loc} || true" &>/dev/null
	echo content > $DIR1/$tdir/$tfile & PID1=$!
	pdo_sched
	multiop $DIR2/$tdir/$tfile u & PID2=$!

	wait $PID1 ||
		{ ret=$?; \
		echo -n "overwriting $tfile should succeed (err=$ret); "; }
	wait $PID2 ||
		{ ret=$?; \
		echo -n "unlinking $tfile should succeed (err=$ret);"; }

	#Clean
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x0 || true" &>/dev/null
	rm -rf $DIR/$tdir

	return $ret
}

test_43k() {
	[[ $MDS1_VERSION -le $(version_code 2.13.56) ]] ||
		skip "Need MDS version newer than 2.13.56"
	local msg fail_loc

#define OBD_FAIL_ONCE|OBD_FAIL_MDS_REINT_OPEN         0x169
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_REINT_OPEN2        0x16a
	for fail_loc in "0x80000169" "0x8000016a"; do
		echo "Begin 100 tests with fail_loc=$fail_loc"
		printf "Progress: "
		for i in {1..100}; do
			printf "*"
			msg=$(sub_test_43k "$fail_loc") ||
				{ echo; error "iter=$i : $msg"; }
		done
		echo
	done

	#Clean
	reset_fail_loc

	return 0
}
run_test 43k "unlink vs create"

# test 44: rename tgt and blocking operations
test_44a() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2   0x146
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000146 2>/dev/null || true"
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mkdir $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; date;error "mkdir isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "mkdir must fail"
	date
	rm -rf $DIR/$tfile*
	return 0
}
run_test 44a "pdirops: rename tgt vs mkdir =============="

test_44b() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000146 2>/dev/null || true"
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "create must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 44b "pdirops: rename tgt vs create =============="

test_44c() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000146 2>/dev/null || true"
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	link $DIR2/$tfile-3 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "link must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 44c "pdirops: rename tgt vs link =============="

test_44d() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000146 2>/dev/null || true"
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	rm $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "unlink must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 44d "pdirops: rename tgt vs unlink =============="

test_44e() {
	pdo_lru_clear
	touch $DIR1/$tfile
	touch $DIR1/$tfile-2
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000146 2>/dev/null || true"
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile-3 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rename must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 44e "pdirops: rename tgt and rename (tgt) =============="

test_44f() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000146 2>/dev/null || true"
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile $DIR2/$tfile-3 &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rename must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 44f "pdirops: rename tgt and rename (src) =============="

test_44g() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000146 2>/dev/null || true"
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	stat $DIR2/$tfile > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "stat must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 44g "pdirops: rename tgt vs getattr =============="

test_44h() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2    0x146
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000146 2>/dev/null || true"
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	ls -lia $DIR2/ > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	wait $PID2
	rm -rf $DIR/$tfile*
	return 0
}
run_test 44h "pdirops: rename tgt vs readdir =============="

# test 44: rename tgt and blocking operations
test_44i() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK2   0x146
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000146 2>/dev/null || true"
	mv $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	$LFS mkdir -i 1 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1;
				error "remote mkdir isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "remote mkdir must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 44i "pdirops: rename tgt vs remote mkdir"

# test 45: rename,mkdir doesn't fail with -EEXIST
test_45a() {
	for i in {1..1000}; do
		mkdir $DIR1/$tdir || error "mkdir $tdir failed"
		mrename $DIR2/$tdir $DIR2/$tdir.$i > /dev/null ||
			error "mrename to $tdir.$i failed"
	done
	rm -rf $DIR/$tdir*
	return 0
}
run_test 45a "rename,mkdir doesn't return -EEXIST =============="

test_45b() {
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$! ; pdo_sched
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "create must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 45b "pdirops: rename src vs create =============="

test_45c() {
	pdo_lru_clear
	touch $DIR1/$tfile
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$! ; pdo_sched
	link $DIR2/$tfile-3 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "link must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 45c "pdirops: rename src vs link =============="

test_45d() {
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$! ; pdo_sched
	rm $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "unlink must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 45d "pdirops: rename src vs unlink =============="

test_45e() {
	pdo_lru_clear
	touch $DIR1/$tfile
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile-3 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rename must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 45e "pdirops: rename src and rename (tgt) =============="

test_45f() {
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile $DIR2/$tfile-3 &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "rename must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 45f "pdirops: rename src and rename (src) =============="

test_45g() {
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$! ; pdo_sched
	stat $DIR2/$tfile > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "stat must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 45g "pdirops: rename src vs getattr =============="

test_45h() {
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$! ; pdo_sched
	ls -lia $DIR2/ > /dev/null &
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	wait $PID2
	rm -rf $DIR/$tfile*
	return 0
}
run_test 45h "pdirops: unlink vs readdir =============="

test_45i() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	pdo_lru_clear
	touch $DIR1/$tfile
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	mv $DIR1/$tfile $DIR1/$tfile-2 &
	PID1=$! ; pdo_sched
	$LFS mkdir -i 1 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1;
				error "create remote dir isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "create remote dir must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 45i "pdirops: rename src vs remote mkdir"

sub_test_45j() {
	local PID1 PID2
	local fail_loc="$1"
	local ret=0

	# We test in a sparate directory to be able to unblock server thread in
	# cfs_race if LCK_PW is taken on the parent by mdt_reint_rename.
	test_mkdir $DIR2/$tdir
	echo file1 > $DIR2/$tdir/$tfile
	echo file2 > $DIR2/$tdir/$tfile-2

	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=${fail_loc} || true" &>/dev/null

	cat $DIR1/$tdir/$tfile >/dev/null &
	PID1=$!
	pdo_sched
	mrename $DIR2/$tdir/$tfile-2 $DIR2/$tdir/$tfile > /dev/null &
	PID2=$!

	wait $PID1 ||
		{ ret=$?; echo -n "cat $tfile should succeed (err=$ret); "; }
	wait $PID2 ||
		{ ret=$?; \
		echo -n "mrename $tfile-2 to $tfile failed (err=$ret);"; }

	#Clean
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x0 || true" &>/dev/null
	rm -rf $DIR/$tdir

	return $ret
}

test_45j() {
	[[ $MDS1_VERSION -le $(version_code 2.13.56) ]] ||
		skip "Need MDS version newer than 2.13.56"
	local msg fail_loc

#define OBD_FAIL_ONCE|OBD_FAIL_MDS_REINT_OPEN         0x169
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_REINT_OPEN2        0x16a
	for fail_loc in "0x80000169" "0x8000016a"; do
		echo "Begin 100 tests with fail_loc=$fail_loc"
		printf "Progress: "
		for i in {1..100}; do
			printf "*"
			msg=$(sub_test_45j "$fail_loc") ||
				{ echo; error "iter=$i : $msg"; }
		done
		echo
	done
}
run_test 45j "read vs rename =============="

# test 46: link and blocking operations
test_46a() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mkdir $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "mkdir isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "mkdir must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 46a "pdirops: link vs mkdir =============="

test_46b() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	$MULTIOP $DIR2/$tfile oO_CREAT:O_EXCL:c &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "create must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 46b "pdirops: link vs create =============="

test_46c() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	link $DIR2/$tfile $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "link must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 46c "pdirops: link vs link =============="

test_46d() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	rm $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "unlink isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "unlink must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 46d "pdirops: link vs unlink =============="

test_46e() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile-3 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rename must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 46e "pdirops: link and rename (tgt) =============="

test_46f() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
	touch $DIR1/$tfile-3
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile $DIR2/$tfile-3 &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "rename isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rename must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 46f "pdirops: link and rename (src) =============="

test_46g() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	stat $DIR2/$tfile > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "getattr isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "stat must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 46g "pdirops: link vs getattr =============="

test_46h() {
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	ls -lia $DIR2/ > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	wait $PID2
	rm -rf $DIR/$tfile*
	return 0
}
run_test 46h "pdirops: link vs readdir =============="

test_46i() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	link $DIR1/$tfile-2 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	$LFS mkdir -i 1 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1;
				error "remote mkdir isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "remote mkdir must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 46i "pdirops: link vs remote mkdir"

# test 47: remote mkdir and blocking operations
test_47a() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	pdo_lru_clear
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mkdir $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "mkdir isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "mkdir must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 47a "pdirops: remote mkdir vs mkdir"

test_47b() {
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	pdo_lru_clear
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	sleep 1 # please do not remove this sleep, see LU-10754
	multiop $DIR2/$tfile oO_CREAT:O_EXCL:c &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1;
					error "create isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "create must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 47b "pdirops: remote mkdir vs create"

test_47c() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	link $DIR2/$tfile-2 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1; error "link isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "link must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 47c "pdirops: remote mkdir vs link"

test_47d() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	rmdir $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1;
					error "unlink isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rmdir must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 47d "pdirops: remote mkdir vs unlink"

test_47e() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	pdo_lru_clear
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mv -T $DIR2/$tfile-2 $DIR2/$tfile &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1;
					error "rename isn't blocked"; }
	wait $PID2 ; [ $? -ne 0 ] || error "rename must fail"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 47e "pdirops: remote mkdir and rename (tgt)"

test_47f() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	mv $DIR2/$tfile $DIR2/$tfile-2 &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1;
					error "rename isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "rename must succeed"
	rm -rf $DIR/$tfile*
	return 0
}
run_test 47f "pdirops: remote mkdir and rename (src)"

test_47g() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return
	sync
	sync_all_data
	pdo_lru_clear
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0x80000145 2>/dev/null || true"
	$LFS mkdir -i 1 $DIR1/$tfile &
	PID1=$! ; pdo_sched
	stat $DIR2/$tfile > /dev/null &
	PID2=$! ; pdo_sched
	do_nodes $(comma_list $(mdts_nodes)) \
		"lctl set_param -n fail_loc=0 2>/dev/null || true"
	check_pdo_conflict $PID1 && { wait $PID1;
					error "getattr isn't blocked"; }
	wait $PID2 ; [ $? -eq 0 ] || error "stat must succeed"
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
	for ((i = 0; i < 6; i++)); do
		sleep 1
		kill -0 $pid || break
	done
	kill -0 $pid 2> /dev/null && error "multiop is still there"
	cmp $origfile $DIR2/$tfile || error "$origfile and $DIR2/$tfile differs"

	rm -f $DIR1/$tfile
}
run_test 51a "layout lock: refresh layout should work"

test_51b() {
	(( $MDS1_VERSION >= $(version_code 2.3.59) )) ||
		skip "Need MDS version at least 2.3.59"

	local tmpfile=`mktemp`

	$LFS setstripe -E 1m -S 1M -c 1 -E -1 -c 1 $DIR1/$tfile ||
		error "Create $DIR1/$tfile failed"

	dd if=/dev/zero of=$DIR1/$tfile bs=1k count=1 conv=notrunc ||
		error "dd $DIR1/$tfile failed"

	# delay glimpse so that layout has changed when glimpse finish
#define OBD_FAIL_GLIMPSE_DELAY 0x1404
	$LCTL set_param fail_loc=0x1404 fail_val=4
	stat -c %s $DIR2/$tfile |tee $tmpfile &
	local pid=$!
	sleep 0.2

	# extend layout of testing file
	dd if=/dev/zero of=$DIR1/$tfile bs=1M count=1 seek=2 conv=notrunc ||
		error "dd $DIR1/$tfile failed"

	wait $pid
	local fsize=$(cat $tmpfile)

	[ x$fsize = x3145728 ] || error "file size is $fsize, should be 3145728"

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
	local stripe_count=$($LFS getstripe -c $DIR2/$tdir/$tfile)
	wait $pid

	# lod_qos.c::min_stripe_count() allows setstripe with a default stripe
	# count to succeed with only 3/4 of the number of stripes (rounded up),
	# so creating striped files does not fail if an OST is offline or full
	[ $stripe_count -ge $((OSTCOUNT - $OSTCOUNT / 4)) ] ||
		error "bad layout: getstripe -c $stripe_count < $OSTCOUNT * 3/4"

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

	# cancel layout lock manually
	cancel_lru_locks mdc

	# rss after revoking
	local ar=$(grep -A 10 $tfile /proc/$PID/smaps | awk '/^Rss/{print $2}')

	kill -USR1 $PID
	wait $PID || error "wait PID $PID failed"

	[ $ar -eq 0 ] || error "rss before: $br, after $ar, some pages remained"
}
run_test 51d "layout lock: losing layout lock should clean up memory map region"

test_51e() {
	(( $MDS1_VERSION >= $(version_code 2.13.54.148) )) ||
		skip "MDS version must be at least 2.13.54.148"

	local pid

	$MULTIOP $DIR/$tfile oO_CREAT:O_RDWR:eW_E+eUc &
	pid=$!
	sleep 1

	$LFS getstripe $DIR2/$tfile
	kill -USR1 $pid
	wait $pid || error "multiop failed"

	$MULTIOP $DIR/$tfile oO_RDONLY:eR_E+eUc &
	pid=$!
	sleep 1

	$LFS getstripe $DIR2/$tfile
	kill -USR1 $pid
	wait $pid || error "multiop failed"
}
run_test 51e "lfs getstripe does not break leases, part 2"

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
	mkdir_on_mdt0 $DIR/$tdir
	mkdir -p $DIR/$tdir/d1/d2 $DIR/$tdir/d3 || error "(1) mkdir failed"

#define OBD_FAIL_MDS_RENAME4              0x156
	do_facet mds1 $LCTL set_param fail_loc=0x80000156

	mv -T $DIR/$tdir/d1/d2 $DIR/$tdir/d3/d2 &
	PID1=$!
	sleep 1

	rm -r $DIR2/$tdir/d3
	wait $PID1 && error "(2) mv succeeded"

	rm -rf $DIR/$tdir
}
run_test 55a "rename vs unlink target dir"

test_55b()
{
	mkdir_on_mdt0 $DIR/$tdir
	mkdir -p $DIR/$tdir/d1/d2 $DIR/$tdir/d3 || error "(1) mkdir failed"

#define OBD_FAIL_MDS_RENAME4             0x156
	do_facet mds1 $LCTL set_param fail_loc=0x80000156

	mv -T $DIR/$tdir/d1/d2 $DIR/$tdir/d3/d2 &
	PID1=$!
	sleep 1

	rm -r $DIR2/$tdir/d1
	wait $PID1 && error "(2) mv succeeded"

	rm -rf $DIR/$tdir
}
run_test 55b "rename vs unlink source dir"

test_55c()
{
	mkdir_on_mdt0 $DIR/$tdir
	mkdir -p $DIR/$tdir/d1/d2 $DIR/$tdir/d3 || error "(1) mkdir failed"

#define OBD_FAIL_MDS_RENAME4              0x156
	do_facet mds1 $LCTL set_param fail_loc=0x156

	mv -T $DIR/$tdir/d1/d2 $DIR/$tdir/d3/d2 &
	PID1=$!
	sleep 1

	# while rename is sleeping, open and remove d3
	$MULTIOP $DIR2/$tdir/d3 D_c &
	PID2=$!
	sleep 1
	rm -rf $DIR2/$tdir/d3
	sleep 5

	# while rename is sleeping 2nd time, close d3
	kill -USR1 $PID2
	wait $PID2 || error "(3) multiop failed"

	wait $PID1 && error "(2) mv succeeded"

	rm -rf $DIR/$tdir
}
run_test 55c "rename vs unlink orphan target dir"

test_55d()
{
	mkdir_on_mdt0 $DIR/$tdir

	touch $DIR/$tdir/f1

#define OBD_FAIL_MDS_RENAME3              0x155
	do_facet mds1 $LCTL set_param fail_loc=0x155
	mv $DIR/$tdir/f1 $DIR/$tdir/$tdir &
	PID1=$!
	sleep 2

	# while rename is sleeping, create $tdir, but as a directory
	mkdir -p $DIR2/$tdir/$tdir || error "(1) mkdir failed"

	# link in reverse locking order
	ln $DIR2/$tdir/f1 $DIR2/$tdir/$tdir/

	wait $PID1 && error "(2) mv succeeded"
	rm -rf $DIR/$tdir
}
run_test 55d "rename file vs link"

test_60() {
	[ $MDS1_VERSION -lt $(version_code 2.3.0) ] &&
		skip "MDS version must be >= 2.3.0"

	# Create a file
	test_mkdir $DIR1/$tdir
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
	[[ "$MDS1_VERSION" -lt $(version_code 2.1.6) ]] &&
		skip "Need MDS version at least 2.1.6"

	# Patch not applied to 2.2 and 2.3 branches
	[[ "$MDS1_VERSION" -ge $(version_code 2.2.0) ]] &&
	[[ "$MDS1_VERSION" -lt $(version_code 2.4.0) ]] &&
		skip "Need MDS version earlier than 2.2.0 or at least 2.4.0"

	checkfiemap --test ||
		skip "checkfiemap not runnable: $?"
	# write data this way: hole - data - hole - data
	dd if=/dev/urandom of=$DIR1/$tfile bs=40K seek=1 count=1
	[ "$(facet_fstype ost$(($($LFS getstripe -i $DIR1/$tfile) + 1)))" = \
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
	[[ "$MDS1_VERSION" -lt $(version_code 2.1.6) ]] &&
		skip "Need MDS version at least 2.1.6"

	# Patch not applied to 2.2 and 2.3 branches
	[[ "$MDS1_VERSION" -ge $(version_code 2.2.0) ]] &&
	[[ "$MDS1_VERSION" -lt $(version_code 2.4.0) ]] &&
		skip "Need MDS version earlier than 2.2.0 or at least 2.4.0"
	[[ $OSTCOUNT -ge 2 ]] || skip "needs >= 2 OSTs"

	checkfiemap --test ||
		skip "error $?: checkfiemap failed"

	mkdir -p $DIR1/$tdir

	$LFS setstripe -c -1 $DIR1/$tdir || error "setstripe failed"
	dd if=/dev/urandom of=$DIR1/$tdir/$tfile bs=40K count=1
	[ "$(facet_fstype ost$(($($LFS getstripe -i $DIR1/$tdir/$tfile) + 1)))" = \
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
	[ "$MDS1_VERSION" -lt $(version_code 2.4.93) ] &&
		skip "Need MDS version at least 2.4.93"

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
	[[ "$MDS1_VERSION" -lt $(version_code 2.5.53) ]] &&
		skip "Need MDS version at least 2.5.53"

	remote_mds_nodsh && skip "remote MDS with nodsh"
	local fcount=$((MDSCOUNT * 256))
	declare -a fd_list
	declare -a fid_list

	if remote_mds; then
		nid=$($LCTL list_nids | sed  "s/\./\\\./g")
	else
		nid="0@lo"
	fi

	rm -rf $DIR/$tdir
	test_mkdir $DIR/$tdir

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
		dd if=/dev/zero of="$dir/nrs_r_\$HOSTNAME" bs=1M count=$n ||
		error "dd at 0 on client failed (1)"

	do_nodes $CLIENTS $myRUNAS \
		"declare -a pids_w;
		for ((i = 0; i < $n; i++)); do
			dd if=/dev/zero of=$dir/nrs_w_\$HOSTNAME bs=1M \
seek=\\\$i count=1 conv=notrunc &
			pids_w[\\\$i]=\\\$!;
		done;
		rc_w=0;
		for ((i = 0; i < $n; i++)); do
			wait \\\${pids_w[\\\$i]};
			newrc=\\\$?;
			[ \\\$newrc -gt \\\$rc_w ] && rc_w=\\\$newrc;
		done;
		exit \\\$rc_w" &
	local pid_w=$!
	do_nodes $CLIENTS sync;
	cancel_lru_locks osc

	do_nodes $CLIENTS $myRUNAS \
		"declare -a pids_r;
		for ((i = 0; i < $n; i++)); do
			dd if=$dir/nrs_r_\$HOSTNAME bs=1M of=/dev/null \
seek=\\\$i count=1 &
			pids_r[\\\$i]=\\\$!;
		done;
		rc_r=0;
		for ((i = 0; i < $n; i++)); do
			wait \\\${pids_r[\\\$i]};
			newrc=\\\$?;
			[ \\\$newrc -gt \\\$rc_r ] && rc_r=\\\$newrc;
		done;
		exit \\\$rc_r" &
	local pid_r=$!
	cancel_lru_locks osc

	wait $pid_w || error "dd (write) failed (2)"
	wait $pid_r || error "dd (read) failed (3)"
	rm -rvf $dir || error "rm -rf $dir failed"
}

test_77a() { #LU-3266
	local rc

	oss=$(comma_list $(osts_nodes))
	do_nodes $oss lctl set_param ost.OSS.*.nrs_policies="fifo" ||
		rc=$?
	[[ $rc -eq 3 ]] && skip "no NRS exists" && return
	[[ $rc -ne 0 ]] && error "failed to set fifo policy"
	nrs_write_read

	return 0
}
run_test 77a "check FIFO NRS policy"

test_77b() { #LU-3266
	local rc

	oss=$(comma_list $(osts_nodes))

	do_nodes $oss lctl set_param ost.OSS.*.nrs_policies="crrn" \
		ost.OSS.*.nrs_crrn_quantum=1 || rc=$?
	[[ $rc -eq 3 ]] && skip "no NRS exists" && return
	[[ $rc -ne 0 ]] && error "failed to set crrn_quantum to 1"

	echo "policy: crr-n, crrn_quantum 1"
	nrs_write_read

	do_nodes $oss lctl set_param \
		ost.OSS.*.nrs_crrn_quantum=64 || rc=$?
	[[ $rc -ne 0 ]] && error "failed to set crrn_quantum to 64"

	echo "policy: crr-n, crrn_quantum 64"
	nrs_write_read

	# cleanup
	do_nodes $oss lctl set_param \
		ost.OSS.ost_io.nrs_policies="fifo" || rc=$?
	[[ $rc -ne 0 ]] && error "failed to set fifo policy"
	return 0
}
run_test 77b "check CRR-N NRS policy"

orr_trr() {
	local policy=$1

	oss=$(comma_list $(osts_nodes))

	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies=$policy \
		ost.OSS.*.nrs_"$policy"_quantum=1 \
		ost.OSS.*.nrs_"$policy"_offset_type="physical" \
		ost.OSS.*.nrs_"$policy"_supported="reads" || return $?

	echo "policy: $policy, ${policy}_quantum 1, ${policy}_offset_type " \
		"physical, ${policy}_supported reads"
	nrs_write_read

	do_nodes $oss lctl set_param \
		ost.OSS.*.nrs_${policy}_supported="writes" \
		ost.OSS.*.nrs_${policy}_quantum=64 || return $?

	echo "policy: $policy, ${policy}_quantum 64, ${policy}_offset_type " \
		"physical, ${policy}_supported writes"
	nrs_write_read

	do_nodes $oss lctl set_param \
		ost.OSS.*.nrs_${policy}_supported="reads_and_writes" \
		ost.OSS.*.nrs_${policy}_offset_type="logical" || return $?
	echo "policy: $policy, ${policy}_quantum 64, ${policy}_offset_type " \
		"logical, ${policy}_supported reads_and_writes"
	nrs_write_read

	# cleanup
	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="fifo" ||
		return $?
	return 0
}

test_77c() { #LU-3266
	local rc
	orr_trr "orr" || rc=$?
	[[ $rc -eq 3 ]] && skip "no NRS exists" && return
	[[ $rc -ne 0 ]] && error "orr_trr failed rc:$rc"
	return 0
}
run_test 77c "check ORR NRS policy"

test_77d() { #LU-3266
	local rc
	orr_trr "trr" || rc=$?
	[[ $rc -eq 3 ]] && skip "no NRS exists" && return
	[[ $rc -ne 0 ]] && error "orr_trr failed rc:$rc"
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
	local rc

	oss=$(comma_list $(osts_nodes))

	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="tbf\ nid" ||
		rc=$?
	[[ $rc -eq 3 ]] && skip "no NRS TBF exists" && return
	[[ $rc -ne 0 ]] && error "failed to set TBF NID policy"

	local idis
	local rateis
	if [ "$OST1_VERSION" -ge $(version_code 2.8.54) ]; then
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
	local rc

	oss=$(comma_list $(osts_nodes))

	do_nodes $oss $LCTL set_param \
		ost.OSS.ost_io.nrs_policies="tbf\ jobid" || rc=$?
	[[ $rc -eq 3 ]] && skip "no NRS TBF exists" && return
	[[ $rc -ne 0 ]] && error "failed to set TBF JOBID policy"

	# Configure jobid_var
	local saved_jobid_var=$($LCTL get_param -n jobid_var)
	rc=$?
	[[ $rc -eq 3 ]] && skip "jobid_var not found" && return
	[[ $rc -ne 0 ]] && error "failed to get param jobid_var"
	if [ $saved_jobid_var != procname_uid ]; then
		set_persistent_param_and_check client \
			"jobid_var" "$FSNAME.sys.jobid_var" procname_uid
	fi

	local idis
	local rateis
	if [ "$OST1_VERSION" -ge $(version_code 2.8.54) ]; then
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
	[[ $? -ne 0 ]] && error "failed to get param jobid_var"
	if [ $saved_jobid_var != $current_jobid_var ]; then
		set_persistent_param_and_check client \
			"jobid_var" "$FSNAME.sys.jobid_var" $saved_jobid_var
	fi
	return 0
}
run_test 77f "check TBF JobID nrs policy"

test_77g() {
	local rc=0

	oss=$(comma_list $(osts_nodes))

	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="tbf\ nid" ||
		rc=$?
	[[ $rc -eq 3 ]] && skip "no NRS TBF exists" && return
	[[ $rc -ne 0 ]] && error "failed to set TBF NID policy"

	do_nodes $oss lctl set_param \
		ost.OSS.ost_io.nrs_policies="tbf\ jobid" || rc=$?
	[[ $rc -ne 0 ]] && error "failed to set TBF JOBID policy"

	local idis
	local rateis
	if [ "$OST1_VERSION" -ge $(version_code 2.8.54) ]; then
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
	[ "$OST1_VERSION" -ge $(version_code 2.8.55) ] ||
		skip "Need OST version at least 2.8.55"

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
	[ "$OST1_VERSION" -ge $(version_code 2.8.55) ] ||
		skip "Need OST version at least 2.8.55"

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

	[ "$OST1_VERSION" -ge $(version_code 2.9.53) ] ||
		skip "Need OST version at least 2.9.53"
	if [ "$OST1_VERSION" -ge $(version_code 2.8.60) ]; then
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

test_id() {
	local idstr="${1}id"
	local policy="${idstr}={$2}"
	local rate="rate=$3"

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param jobid_var=procname_uid \
			ost.OSS.ost_io.nrs_policies="tbf\ ${idstr}" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ost_${idstr}\ ${policy}\ ${rate}"
	[ $? -ne 0 ] && error "failed to set tbf ${idstr} policy"

	nrs_write_read "runas $4"
	tbf_verify $3 $3 "runas $4"

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ ost_${idstr}" \
			ost.OSS.ost_io.nrs_policies="fifo"

	# sleep 3 seconds to wait the tbf policy stop completely,
	# or the next test case is possible get -eagain when
	# setting the tbf policy
	sleep 3
}

test_77ja(){
	if [ "$OST1_VERSION" -lt $(version_code 2.11.50) ]; then
		skip "Need OST version at least 2.11.50"
	fi

	test_id "u" "500" "5" "-u 500"
	test_id "g" "500" "5" "-u 500 -g 500"
}
run_test 77ja "check TBF-UID/GID NRS policy"

cleanup_77k()
{
	local rule_lists=$1
	local old_nrs=$2

	trap 0
	for rule in $rule_lists; do
		do_nodes $(comma_list $(osts_nodes)) \
			lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ $rule"
	done

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_policies="$old_nrs"

	sleep 3
}

test_77k() {
	[[ "$OST1_VERSION" -ge $(version_code 2.9.53) ]] ||
		skip "Need OST version at least 2.9.53"

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

	trap "cleanup_77k \"ext_a ext_b\" \"fifo\"" EXIT

	[[ "$OST1_VERSION" -ge $(version_code 2.10.58) ]] ||
		skip "Need OST version at least 2.10.58"

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_a" \
			ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_b" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_ug\ uid={500}\&gid={1000}\ rate=5"
	nrs_write_read "runas -u 500 -g 1000"
	tbf_verify 5 5 "runas -u 500 -g 1000"

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_ug" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_uw\ uid={500}\&opcode={ost_write}\ rate=20" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_ur\ uid={500}\&opcode={ost_read}\ rate=10"

	nrs_write_read "runas -u 500"
	tbf_verify 20 10 "runas -u 500"

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_uw" \
			ost.OSS.ost_io.nrs_tbf_rule="stop\ ext_ur" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_a\ uid={500},opcode={ost_write}\ rate=20" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ ext_b\ uid={500},opcode={ost_read}\ rate=10"
	nrs_write_read "runas -u 500"
	tbf_verify 10 10 "runas -u 500"
	tbf_verify 20 10 "runas -u 500"
	cleanup_77k "ext_a ext_b" "fifo"
}
run_test 77k "check TBF policy with NID/JobID/OPCode expression"

test_77l() {
	[[ "$OST1_VERSION" -ge $(version_code 2.10.56) ]] ||
		skip "Need OST version at least 2.10.56"

	do_facet ost1 lctl set_param ost.OSS.ost_io.nrs_policies="tbf\ nid"
	do_facet ost1 lctl set_param ost.OSS.ost_io.nrs_policies="tbf"

	local output=$(do_facet ost1 lctl get_param \
			ost.OSS.ost_io.nrs_policies | \
			awk '/name: tbf/ {print;exit}' | \
			awk -F ': ' '{print $2}')

	if [ "$output" != "tbf" ]; then
		error "The generic TBF output is '$output', not 'tbf'"
	fi

	do_facet ost1 lctl set_param ost.OSS.ost_io.nrs_policies="fifo"
}
run_test 77l "check the output of NRS policies for generic TBF"

test_77m() {
	if [ "$OST1_VERSION" -lt $(version_code 2.9.54) ]; then
		skip "Need OST version at least 2.9.54"
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
run_test 77m "check NRS Delay slows write RPC processing"

test_77n() { #LU-10802
	if [ "$OST1_VERSION" -lt $(version_code 2.10.58) ]; then
		skip "Need OST version at least 2.10.58"
	fi

	# Configure jobid_var
	local saved_jobid_var=$($LCTL get_param -n jobid_var)
	if [ $saved_jobid_var != procname_uid ]; then
		set_persistent_param_and_check client \
			"jobid_var" "$FSNAME.sys.jobid_var" procname_uid
	fi

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_policies="tbf\ jobid" \
			ost.OSS.ost_io.nrs_tbf_rule="stop\ dd_runas" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ dd_runas\ jobid={*.$RUNAS_ID}\ rate=20"

	nrs_write_read
	tbf_verify 20 20 "$RUNAS"

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ dd_runas" \
			ost.OSS.ost_io.nrs_tbf_rule="start\ dd_runas\ jobid={dd.*}\ rate=20"

	nrs_write_read
	tbf_verify 20 20

	do_nodes $(comma_list $(osts_nodes)) \
		lctl set_param ost.OSS.ost_io.nrs_tbf_rule="stop\ dd_runas" \
			ost.OSS.ost_io.nrs_policies="fifo"

	sleep 3

	local current_jobid_var=$($LCTL get_param -n jobid_var)
	if [ $saved_jobid_var != $current_jobid_var ]; then
		set_persistent_param_and_check client \
			"jobid_var" "$FSNAME.sys.jobid_var" $saved_jobid_var
	fi
}
run_test 77n "check wildcard support for TBF JobID NRS policy"

test_77o() {
	(( $OST1_VERSION > $(version_code 2.14.54) )) ||
        	skip "need OST > 2.14.54"

	do_facet mds1 $LCTL set_param mds.MDS.mdt.nrs_policies="tbf\ nid"
	do_facet mds1 $LCTL set_param mds.MDS.mdt.nrs_tbf_rule="start\ name\ nid={192.168.*.*@tcp}\ rate=10000"
	do_facet mds1 $LCTL set_param mds.MDS.mdt.nrs_tbf_rule="start\ name1\ nid={192.168.*.*@tcp}\ rate=10000"
	do_facet mds1 $LCTL set_param mds.MDS.mdt.nrs_tbf_rule="change\ name1\ rank=name"
	do_facet mds1 $LCTL set_param mds.MDS.mdt.nrs_tbf_rule="stop\ name"
	do_facet mds1 $LCTL set_param mds.MDS.mdt.nrs_policies="fifo"
}
run_test 77o "Changing rank should not panic"

test_78() { #LU-6673
	local rc

	oss=$(comma_list $(osts_nodes))
	do_nodes $oss lctl set_param ost.OSS.ost_io.nrs_policies="orr" &
	do_nodes $oss lctl set_param ost.OSS.*.nrs_orr_quantum=1
	rc=$?
	[[ $rc -eq 3 ]] && skip "no NRS exists" && return
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
	test_mkdir $DIR/$tdir

	# Prevent interference from layout intent RPCs due to
	# asynchronous writeback. These will be tested in 130c below.
	do_nodes ${CLIENTS:-$HOSTNAME} sync

	setfattr -n trusted.name1 -v value1 $DIR/$tdir ||
		error "setfattr -n trusted.name1=value1 $DIR/$tdir failed"

#define OBD_FAIL_MDS_INTENT_DELAY		0x160
	local mdtidx=$($LFS getstripe -m $DIR/$tdir)
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
		mdt_index=$($LFS getstripe -m $file)
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

test_81a() {
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
run_test 81a "rename and stat under striped directory"

test_81b() {
	[ $MDSCOUNT -lt 2 ] &&
		skip "We need at least 2 MDTs for this test"

	local total
	local setattr_pid

	total=1000

	$LFS mkdir -c $MDSCOUNT $DIR1/$tdir || error "$LFS mkdir"
	createmany -o $DIR1/$tdir/$tfile. $total || error "createmany"

	(
		while true; do
			touch $DIR1/$tdir
		done
	) &
	setattr_pid=$!

	for i in $(seq $total); do
		mrename $DIR2/$tdir/$tfile.$i $DIR2/$tdir/$tfile-new.$i \
			> /dev/null
	done

	kill -9 $setattr_pid
}
run_test 81b "rename under striped directory doesn't deadlock"

test_81c() {
	[ $MDSCOUNT -lt 4 ] && skip_env "needs >= 4 MDTs"
	[ $MDS1_VERSION -lt $(version_code 2.13.52) ] &&
		skip "Need MDS version at least 2.13.52"

	# source is local, source parent is remote
	$LFS mkdir -i 0 $DIR1/${tdir}_src || error "mkdir ${tdir}_src"
	$LFS mkdir -i 1 $DIR1/${tdir}_tgt || error "mkdir ${tdir}_tgt"
	$LFS mkdir -i 3 $DIR1/${tdir}_src/sub || error "mkdir sub"
	$LFS mkdir -i 3 $DIR1/${tdir}_tgt/sub || error "mkdir sub"
	stat $DIR2/${tdir}_src/sub || error "stat sub failed"
	mv $DIR1/${tdir}_src/sub $DIR1/${tdir}_tgt/ || error "mv failed"
	[ -f $DIR2/${tdir}_src/sub ] && error "sub should be gone"
	rm -rf $DIR1/${tdir}_src $DIR1/${tdir}_tgt

	# source is remote, source parent is local
	$LFS mkdir -i 3 $DIR1/${tdir}_src || error "mkdir ${tdir}_src"
	$LFS mkdir -i 1 $DIR1/${tdir}_tgt || error "mkdir ${tdir}_tgt"
	$LFS mkdir -i 0 $DIR1/${tdir}_src/sub || error "mkdir sub"
	$LFS mkdir -i 3 $DIR1/${tdir}_tgt/sub || error "mkdir sub"
	stat $DIR2/${tdir}_src/sub || error "stat sub failed"
	mv $DIR1/${tdir}_src/sub $DIR1/${tdir}_tgt/ || error "mv failed"
	[ -f $DIR2/${tdir}_src/sub ] && error "sub should be gone"
	rm -rf $DIR1/${tdir}_src $DIR1/${tdir}_tgt

	# source and source parent are remote
	$LFS mkdir -i 0 $DIR1/${tdir}_src || error "mkdir ${tdir}_src"
	$LFS mkdir -i 1 $DIR1/${tdir}_tgt || error "mkdir ${tdir}_tgt"
	mkdir $DIR1/${tdir}_src/sub || error "mkdir sub"
	$LFS mkdir -i 3 $DIR1/${tdir}_tgt/sub || error "mkdir sub"
	stat $DIR2/${tdir}_src/sub || error "stat sub failed"
	mv $DIR1/${tdir}_src/sub $DIR1/${tdir}_tgt/ || error "mv failed"
	[ -f $DIR2/${tdir}_src/sub ] && error "sub should be gone"
	rm -rf $DIR1/${tdir}_src $DIR1/${tdir}_tgt

	# source and source parent are remote, and source is remote object
	$LFS mkdir -i 0 $DIR1/${tdir}_src || error "mkdir ${tdir}_src"
	$LFS mkdir -i 1 $DIR1/${tdir}_tgt || error "mkdir ${tdir}_tgt"
	$LFS mkdir -i 2 $DIR1/${tdir}_src/sub || error "mkdir sub"
	$LFS mkdir -i 3 $DIR1/${tdir}_tgt/sub || error "mkdir sub"
	stat $DIR2/${tdir}_src/sub || error "stat sub failed"
	mv $DIR1/${tdir}_src/sub $DIR1/${tdir}_tgt/ || error "mv failed"
	[ -f $DIR2/${tdir}_src/sub ] && error "sub should be gone" || true
}
run_test 81c "rename revoke LOOKUP lock for remote object"

test_82() {
	[[ "$MDS1_VERSION" -gt $(version_code 2.6.91) ]] ||
		skip "Need MDS version at least 2.6.92"

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

test_84() {
	[ $MDS1_VERSION -lt $(version_code 2.12.55) ] &&
		skip "lustre < 2.12.55 does not contain LU-12485 fix"

	local mtime

	$MULTIOP $DIR/$tfile oO_RDWR:O_CREAT:O_LOV_DELAY_CREATE:c ||
		error "create $tfile failed"
	mtime=$(stat -c%Y $DIR/$tfile)
	mtime=$((mtime + 200))

	#define OBD_FAIL_OBD_0NLINK_RACE  0x60b
	do_facet mds1 $LCTL set_param fail_loc=0x8000060b

	touch -c -m $mtime $DIR/$tfile &
	setattr_pid=$!
	# sleep a while to let 'touch' run first
	sleep 5
	rm -f $DIR2/$tfile || error "unlink $tfile failed"

	# touch may fail
	wait $setattr_pid || true
}
run_test 84 "0-nlink race in lu_object_find()"

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
	local old_rr=$(do_facet $SINGLEMDS "$LCTL get_param -n \
		lod.$FSNAME-MDT0000-*/qos_threshold_rr" | sed -e 's/%//')
	do_facet $SINGLEMDS "$LCTL set_param -n \
		lod.$FSNAME-MDT0000-*/qos_threshold_rr=100"
	#define OBD_FAIL_MDS_LOV_CREATE_RACE     0x163
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x00000163"

	$LFS setstripe -c -1 $DIR1/$tfile-1/file1 &
	local PID1=$!
	sleep 1
	$LFS setstripe -c -1 $DIR2/$tfile-2/file2 &
	local PID2=$!
	wait $PID2
	wait $PID1
	do_facet $SINGLEMDS "$LCTL set_param fail_loc=0x0"
	do_facet $SINGLEMDS "$LCTL set_param -n \
		lod.$FSNAME-MDT0000-*/qos_threshold_rr=$old_rr"

	$LFS getstripe $DIR1/$tfile-1/file1
	rc1=$($LFS getstripe -q $DIR1/$tfile-1/file1 |
		awk '{if (/[0-9]/) print $1 }' | sort | uniq -d | wc -l)
	$LFS getstripe $DIR2/$tfile-2/file2
	rc2=$($LFS getstripe -q $DIR2/$tfile-2/file2 |
		awk '{if (/[0-9]/) print $1 }' | sort | uniq -d | wc -l)
	echo "rc1=$rc1 and rc2=$rc2 "
	[ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] ||
		error "object allocate on same ost detected"
}
run_test 93 "alloc_rr should not allocate on same ost"

test_94() {
	$LCTL set_param osc.*.idle_timeout=0
	dd if=/dev/zero of=$DIR2/$tfile bs=4k count=2 conv=fsync

	local before=$(date +%s)
	local evict

	$LCTL mark write
#define OBD_FAIL_LDLM_PAUSE_CANCEL       0x312
	$LCTL set_param fail_val=5 fail_loc=0x80000312
	dd if=/dev/zero of=$DIR/$tfile conv=notrunc oflag=append bs=4k count=1 &
	local pid=$!
	sleep 2

#define OBD_FAIL_LDLM_PAUSE_CANCEL_LOCAL 0x329
	$LCTL set_param fail_val=6 fail_loc=0x80000329
	$LCTL mark kill $pid
	kill -ALRM $pid

	dd if=/dev/zero of=$DIR2/$tfile conv=notrunc oflag=append bs=4k count=1

	wait $pid
	dd if=/dev/zero of=$DIR/$tfile bs=4k count=1 conv=fsync

	evict=$(do_facet client $LCTL get_param \
		osc.$FSNAME-OST*-osc-*/state |
	    awk -F"[ [,]" '/EVICTED ]$/ { if (t<$5) {t=$5;} } END { print t }')

	[ -z "$evict" ] || [[ $evict -le $before ]] ||
		(do_facet client $LCTL get_param \
			osc.$FSNAME-OST*-osc-*/state;
		    error "eviction happened: $evict before:$before")
	$LCTL set_param osc.*.idle_timeout=debug
}
run_test 94 "signal vs CP callback race"

# Data-on-MDT tests
test_100a() {
	skip "Reserved for glimpse-ahead" && return
	[ "$MDS1_VERSION" -lt $(version_code 2.10.55) ] &&
		skip "Need MDS version at least 2.10.55"

	mkdir -p $DIR/$tdir

	$LFS setstripe -E 1024K -L mdt -E EOF $DIR/$tdir/dom

	lctl set_param -n mdc.*.stats=clear
	dd if=/dev/zero of=$DIR2/$tdir/dom bs=4096 count=1 || return 1

	$CHECKSTAT -t file -s 4096 $DIR/$tdir/dom || error "stat #1"
	# first stat from server should return size data and save glimpse
	local gls=$(lctl get_param -n mdc.*.stats | grep -c ldlm_glimpse)
	[ $gls -eq 0 ] || error "Unexpected $gls glimpse RPCs"
	# second stat to check size is NOT cached on client without IO lock
	$CHECKSTAT -t file -s 4096 $DIR/$tdir/dom || error "stat #2"

	local gls=$(lctl get_param -n mdc.*.stats | grep -c ldlm_glimpse)
	[ $gls -ge 1 ] || error "Expect glimpse RPCs but none"
	rm -f $dom
}
run_test 100a "DoM: glimpse RPCs for stat without IO lock (DoM only file)"

test_100b() {
	[ "$MDS1_VERSION" -lt $(version_code 2.10.55) ] &&
		skip "Need MDS version at least 2.10.55"

	mkdir -p $DIR/$tdir

	$LFS setstripe -E 1024K -L mdt -E EOF $DIR/$tdir/dom

	lctl set_param -n mdc.*.stats=clear
	dd if=/dev/zero of=$DIR2/$tdir/dom bs=4096 count=1 || return 1
	cancel_lru_locks mdc
	# first stat data from server should have size
	$CHECKSTAT -t file -s 4096 $DIR/$tdir/dom || error "stat #1"
	# second stat to check size is cached on client
	$CHECKSTAT -t file -s 4096 $DIR/$tdir/dom || error "stat #2"

	local gls=$(lctl get_param -n mdc.*.stats | grep -c ldlm_glimpse)
	# both stats should cause no glimpse requests
	[ $gls == 0 ] || error "Unexpected $gls glimpse RPCs"
	rm -f $dom
}
run_test 100b "DoM: no glimpse RPC for stat with IO lock (DoM only file)"

test_100c() {
	[ "$MDS1_VERSION" -lt $(version_code 2.10.55) ] &&
		skip "Need MDS version at least 2.10.55"

	mkdir -p $DIR/$tdir

	$LFS setstripe -E 1024K -L mdt -E EOF $DIR/$tdir/dom

	lctl set_param -n mdc.*.stats=clear
	lctl set_param -n osc.*.stats=clear
	dd if=/dev/zero of=$DIR2/$tdir/dom bs=2048K count=1 || return 1

	# check that size is merged from MDT and OST correctly
	$CHECKSTAT -t file -s 2097152 $DIR/$tdir/dom ||
		error "Wrong size from stat #1"

	local gls=$(lctl get_param -n osc.*.stats | grep -c ldlm_glimpse)
	[ $gls -eq 0 ] && error "Expect OST glimpse RPCs but got none"

	rm -f $dom
}
run_test 100c "DoM: write vs stat without IO lock (combined file)"

test_100d() {
	[ "$MDS1_VERSION" -lt $(version_code 2.10.55) ] &&
		skip "Need MDS version at least 2.10.55"

	mkdir -p $DIR/$tdir

	$LFS setstripe -E 1024K -L mdt -E EOF $DIR/$tdir/dom


	dd if=/dev/zero of=$DIR2/$tdir/dom bs=2048K count=1 || return 1
	lctl set_param -n mdc.*.stats=clear
	$TRUNCATE $DIR2/$tdir/dom 4096

	# check that reported size is valid after file grows to OST and
	# is truncated back to MDT stripe size
	$CHECKSTAT -t file -s 4096 $DIR/$tdir/dom ||
		error "Wrong size from stat #1"

	local gls=$(lctl get_param -n osc.*.stats | grep -c ldlm_glimpse)
	[ $gls -eq 0 ] && error "Expect OST glimpse but got none"

	rm -f $dom
}
run_test 100d "DoM: write+truncate vs stat without IO lock (combined file)"

test_100e() {
	[ "$MDS1_VERSION" -lt $(version_code 2.11.50) ] &&
		skip "Need MDS version at least 2.11.50"

	local dom=$DIR/$tdir/dom
	local dom2=$DIR2/$tdir/dom
	mkdir -p $DIR/$tdir

	$LFS setstripe -E 1024K -L mdt $DIR/$tdir

	cancel_lru_locks mdc
	dd if=/dev/urandom of=$dom bs=12000 count=1
	$TRUNCATE $dom2 6000
	cancel_lru_locks mdc
	lctl set_param -n mdc.*.stats=clear
	# expect read-on-open to return all data before write
	cat /etc/hosts >> $dom
	local read=$(lctl get_param -n mdc.*.stats | grep -c ost_read)
	[[ $read -eq 0 ]] || error "Unexpected $read READ RPCs"
}
run_test 100e "DoM: read on open and file size"

test_101a() {
	[ "$MDS1_VERSION" -lt $(version_code 2.10.55) ] &&
		skip "Need MDS version at least 2.10.55"

	$LFS setstripe -E 1024K -L mdt -E EOF $DIR1/$tfile
	# to get layout
	$CHECKSTAT -t file $DIR1/$tfile

	local old_wb=$(sysctl -n vm.dirty_writeback_centisecs)
	sysctl -wq vm.dirty_writeback_centisecs=0

	trap "sysctl -wq vm.dirty_writeback_centisecs=$old_wb" EXIT

	# open + IO lock
	dd if=/dev/zero of=$DIR1/$tfile bs=4096 count=1 ||
		error_noexit "Write fails"
	# must discard pages
	lctl set_param -n mdc.*.stats=clear
	rm $DIR2/$tfile || error "Unlink fails"

	local writes=$(lctl get_param -n mdc.*.stats | grep -c ost_write)
	[ $writes -eq 0 ] || error "Found WRITE RPC but expect none"
}
run_test 101a "Discard DoM data on unlink"

test_101b() {
	[ "$MDS1_VERSION" -lt $(version_code 2.10.55) ] &&
		skip "Need MDS version at least 2.10.55"

	$LFS setstripe -E 1024K -L mdt -E EOF $DIR1/$tfile
	touch $DIR1/${tfile}_2
	# to get layout
	$CHECKSTAT -t file $DIR1/$tfile

	local old_wb=$(sysctl -n vm.dirty_writeback_centisecs)
	sysctl -wq vm.dirty_writeback_centisecs=0

	trap "sysctl -wq vm.dirty_writeback_centisecs=$old_wb" EXIT

	# open + IO lock
	dd if=/dev/zero of=$DIR1/$tfile bs=4096 count=1 || error "Write fails"
	# must discard pages
	lctl set_param -n mdc.*.stats=clear
	mv $DIR2/${tfile}_2 $DIR2/$tfile || error "Rename fails"

	local writes=$(lctl get_param -n mdc.*.stats | grep -c ost_write)
	[ $writes -eq 0 ] || error "Found WRITE RPC but expect none"
}
run_test 101b "Discard DoM data on rename"

test_101c() {
	[ "$MDS1_VERSION" -lt $(version_code 2.10.55) ] &&
		skip "Need MDS version at least 2.10.55"

	$LFS setstripe -E 1024K -L mdt -E EOF $DIR1/$tfile
	# to get layout
	$CHECKSTAT -t file $DIR1/$tfile

	local old_wb=$(sysctl -n vm.dirty_writeback_centisecs)
	sysctl -wq vm.dirty_writeback_centisecs=0

	trap "sysctl -wq vm.dirty_writeback_centisecs=$old_wb" EXIT

	# open + IO lock
	dd if=/dev/zero of=$DIR1/$tfile bs=4096 count=1 || error "Write fails"
	$MULTIOP $DIR1/$tfile O_c &
	MULTIOP_PID=$!
	sleep 1
	lctl set_param -n mdc.*.stats=clear
	rm $DIR2/$tfile > /dev/null || error "Unlink fails for opened file"
	kill -USR1 $MULTIOP_PID && wait $MULTIOP_PID || error "multiop failure"

	local writes=$(lctl get_param -n mdc.*.stats | grep -c ost_write)
	[ $writes -eq 0 ] || error "Found WRITE RPC but expect none"
}
run_test 101c "Discard DoM data on close-unlink"

# test to verify file handle related system calls
# (name_to_handle_at/open_by_handle_at)
# The new system calls are supported in glibc >= 2.14.

# test to verify we can open by handle an unlinked file from > 1 client
# This test opens the file normally on $DIR1, which is on one mount, and then
# opens it by handle on $DIR2, which is on a different mount.
test_102() {
	[ "$MDS1_VERSION" -lt $(version_code 2.11.57) ] &&
		skip "Needs MDS version 2.11.57 or later"

	echo "Test file_handle syscalls" > $DIR/$tfile ||
		error "write failed"
	check_fhandle_syscalls $DIR/$tfile $DIR2 ||
		error "check_fhandle_syscalls $tfile failed"

	# test this is working on DNE directories also
	if (( MDSCOUNT > 1  MDS1_VERSION >= $(version_code 2.14.52) )); then
		$LFS mkdir -i 1 $DIR/$tdir.remote
		cancel_lru_locks mdc
		check_fhandle_syscalls $DIR/$tdir.remote $DIR2 ||
			error "check_fhandle_syscalls $tdir.remote failed"
		$LFS mkdir -c -1 $DIR/$tdir.remote/subdir
		cancel_lru_locks mdc
		check_fhandle_syscalls $DIR/$tdir.remote/subdir $DIR2 ||
			error "check_fhandle_syscalls $tdir.remote/subdir fail"

		$LFS mkdir -c -1 $DIR/$tdir.stripe
		cancel_lru_locks mdc
		check_fhandle_syscalls $DIR/$tdir.stripe $DIR2 ||
			error "check_fhandle_syscalls $tdir.stripe failed"
		$LFS mkdir -c -1 $DIR/$tdir.stripe/subdir
		cancel_lru_locks mdc
		check_fhandle_syscalls $DIR/$tdir.stripe/subdir $DIR2 ||
			error "check_fhandle_syscalls $tdir.stripe/subdir fail"
	fi
}
run_test 102 "Test open by handle of unlinked file"

# Compare file size between first & second mount, ensuring the client correctly
# glimpses even with unused speculative locks - LU-11670
test_103() {
	[ $OST1_VERSION -lt $(version_code 2.10.50) ] &&
		skip "Lockahead needs OST version at least 2.10.50"

	local locktest=23

	test_mkdir -p $DIR/$tdir

	# Force file on to OST0
	$LFS setstripe -i 0 $DIR/$tdir

	# Do not check multiple locks on glimpse
	# OBD_FAIL_OSC_NO_SIZE_DATA 0x415
	$LCTL set_param fail_loc=0x415

	# Delay write commit by 2 seconds to guarantee glimpse wins race
	# The same fail_loc is used on client & server so it can work in the
	# single node sanity setup
	do_facet ost1 $LCTL set_param fail_loc=0x415 fail_val=2

	echo "Incorrect size expected (no glimpse fix):"
	lockahead_test -d $DIR/$tdir -D $DIR2/$tdir -t $locktest -f $tfile
	rc=$?
	if [ $rc -eq 0 ]; then
		echo "This doesn't work 100%, but this is just reproducing the bug, not testing the fix, so OK to not fail test."
	fi

	# guarantee write commit timeout has expired
	sleep 2

	# Clear fail_loc on client
	$LCTL set_param fail_loc=0

	# Delay write commit by 2 seconds to guarantee glimpse wins race
	# OBD_FAIL_OST_BRW_PAUSE_BULK 0x214
	do_facet ost1 $LCTL set_param fail_loc=0x214 fail_val=2

	# Write commit is still delayed by 2 seconds
	lockahead_test -d $DIR/$tdir -D $DIR2/$tdir -t $locktest -f $tfile
	rc=$?
	[ $rc -eq 0 ] || error "Lockahead test$locktest failed, $rc"

	# guarantee write commit timeout has expired
	sleep 2

	rm -f $DIR/$tfile || error "unable to delete $DIR/$tfile"
}
run_test 103 "Test size correctness with lockahead"

get_stat_xtimes()
{
	local xtimes

	xtimes=$(stat -c "%X %Y %Z" $DIR/$tfile)

	echo ${xtimes[*]}
}

get_mdt_xtimes()
{
	local mdtdev=$1
	local output
	local xtimes

	output=$(do_facet mds1 "$DEBUGFS -c -R 'stat ROOT/$tfile' $mdtdev")
	((xtimes[0]=$(awk -F ':' /atime/'{ print $2 }' <<< "$output")))
	((xtimes[1]=$(awk -F ':' /mtime/'{ print $2 }' <<< "$output")))
	((xtimes[2]=$(awk -F ':' /ctime/'{ print $2 }' <<< "$output")))

	echo ${xtimes[*]}
}

check_mdt_xtimes()
{
	local mdtdev=$1
	local xtimes=($(get_stat_xtimes))
	local mdt_xtimes=($(get_mdt_xtimes $mdtdev))

	echo "STAT a|m|ctime ${xtimes[*]}"
	echo "MDT a|m|ctime ${mdt_xtimes[*]}"
	[[ ${xtimes[0]} == ${mdt_xtimes[0]} ]] ||
		error "$DIR/$tfile atime (${xtimes[0]}:${mdt_xtimes[0]}) diff"
	[[ ${xtimes[1]} == ${mdt_xtimes[1]} ]] ||
		error "$DIR/$tfile mtime (${xtimes[1]}:${mdt_xtimes[1]}) diff"
	[[ ${xtimes[2]} == ${mdt_xtimes[2]} ]] ||
		error "$DIR/$tfile ctime (${xtimes[2]}:${mdt_xtimes[2]}) diff"
}

test_104() {
	[ "$mds1_FSTYPE" == "ldiskfs" ] || skip_env "ldiskfs only test"
	[ $MDS1_VERSION -lt $(version_code 2.12.4) ] &&
		skip "Need MDS version at least 2.12.4"

	local pid
	local mdtdev=$(mdsdevname ${SINGLEMDS//mds/})
	local atime_diff=$(do_facet $SINGLEMDS \
		lctl get_param -n mdd.*MDT0000*.atime_diff)

	do_facet $SINGLEMDS \
		lctl set_param -n mdd.*MDT0000*.atime_diff=0

	stack_trap "do_facet $SINGLEMDS \
		lctl set_param -n mdd.*MDT0000*.atime_diff=$atime_diff" EXIT

	dd if=/dev/zero of=$DIR/$tfile bs=1k count=1 conv=notrunc
	check_mdt_xtimes $mdtdev
	sleep 2

	dd if=/dev/zero of=$DIR/$tfile bs=1k count=1 conv=notrunc
	check_mdt_xtimes $mdtdev
	sleep 2
	$MULTIOP $DIR2/$tfile Oz8192w8192_c &
	pid=$!
	sleep 2
	dd if=/dev/zero of=$DIR/$tfile bs=1k count=1 conv=notrunc
	sleep 2
	kill -USR1 $pid && wait $pid || error "multiop failure"
	check_mdt_xtimes $mdtdev

	local xtimes
	local mdt_xtimes

	# Verify mtime/ctime is NOT upated on MDS when there is no modification
	# on the client side
	xtimes=($(get_stat_xtimes))
	$MULTIOP $DIR/$tfile O_c &
	pid=$!
	sleep 2
	kill -USR1 $pid && wait $pid || error "multiop failure"
	mdt_xtimes=($(get_mdt_xtimes $mdtdev))
	[[ ${xtimes[1]} == ${mdt_xtimes[1]} ]] ||
		error "$DIR/$tfile mtime (${xtimes[1]}:${mdt_xtimes[1]}) diff"
	[[ ${xtimes[2]} == ${mdt_xtimes[2]} ]] ||
		error "$DIR/$tfile ctime (${xtimes[2]}:${mdt_xtimes[2]}) diff"
	check_mdt_xtimes $mdtdev

	sleep 2
	# Change ctime via chmod
	$MULTIOP $DIR/$tfile o_tc &
	pid=$!
	sleep 2
	kill -USR1 $pid && wait $pid || error "multiop failure"
	check_mdt_xtimes $mdtdev
}
run_test 104 "Verify that MDS stores atime/mtime/ctime during close"

test_105() {
	test_mkdir -p $DIR/$tdir
	echo test > $DIR/$tdir/$tfile
	$LCTL set_param fail_loc=0x416
	cancel_lru_locks osc & sleep 1
	fsize1=$(stat -c %s $DIR2/$tdir/$tfile)
	wait
	[[ $fsize1 = 5 ]] ||  error "Glimpse returned wrong file size $fsize1"
}
run_test 105 "Glimpse and lock cancel race"

test_106a() {
	[ "$mds1_FSTYPE" == "ldiskfs" ] && statx_supported ||
		skip_env "Test only for ldiskfs and statx() supported"

	local btime
	local mdt_btime
	local output
	local mdtdev=$(mdsdevname ${SINGLEMDS//mds/})

	dd if=/dev/zero of=$DIR/$tfile bs=1k count=1 conv=notrunc
	btime=$($STATX -c %W $DIR/$tfile)
	output=$(do_facet mds1 "$DEBUGFS -c -R 'stat ROOT/$tfile' $mdtdev")
	echo $output
	((mdt_btime=$(awk -F ':' /crtime/'{ print $2 }' <<< "$output")))
	[[ $btime == $mdt_btime ]] ||
		error "$DIR/$tfile btime ($btime:$mdt_btime) diff"

}
run_test 106a "Verify the btime via statx()"

test_106b() {
	statx_supported || skip_env "statx() only test"

	local rpcs_before
	local rpcs_after

	$LFS setstripe -c 1 $DIR/$tfile || error "$DIR/$tfile setstripe failed"
	dd if=/dev/zero of=$DIR/$tfile bs=1k count=1 conv=notrunc
	cancel_lru_locks $OSC
	rpcs_before=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	$STATX $DIR/$tfile
	rpcs_after=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	[ $rpcs_after -eq $((rpcs_before + 1)) ] ||
		error "$STATX should send 1 glimpse RPC to $OSC"

	cancel_lru_locks $OSC
	rpcs_before=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	# %n: FILENAME; %i: STATX_INO; %A STATX_MODE; %h STATX_NLINK;
	# %u: STATX_UID; %g: STATX_GID; %W STATX_BTIME; %X STATX_ATIME;
	# %Z: STATX_CTIME
	$STATX -c "%n %i %A %h %u %g %W %X %Z" $DIR/$tfile
	rpcs_after=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	[ $rpcs_after -eq $rpcs_before ] ||
		error "$STATX should not send glimpse RPCs to $OSC"

	cancel_lru_locks $OSC
	rpcs_before=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	$STATX --cached=always $DIR/$tfile
	rpcs_after=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	[ $rpcs_after -eq $rpcs_before ] ||
		error "$STATX should not send glimpse RPCs to $OSC"

	cancel_lru_locks $OSC
	rpcs_before=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	$STATX -c %Y $DIR/$tfile
	rpcs_after=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	[ $rpcs_after -eq $((rpcs_before + 1)) ] ||
		error "$STATX -c %Y should send 1 glimpse RPC to $OSC"

	cancel_lru_locks $OSC
	rpcs_before=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	$STATX -c %s $DIR/$tfile
	rpcs_after=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	[ $rpcs_after -eq $((rpcs_before + 1)) ] ||
		error "$STATX -c %s should send 1 glimpse RPC to $OSC"

	cancel_lru_locks $OSC
	rpcs_before=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	$STATX -c %b $DIR/$tfile
	rpcs_after=$(calc_stats $OSC.*$OSC*.stats ldlm_glimpse_enqueue)
	[ $rpcs_after -eq $((rpcs_before + 1)) ] ||
		error "$STATX -c %b should send 1 glimpse RPC to $OSC"
}
run_test 106b "Glimpse RPCs test for statx"

test_106c() {
	statx_supported || skip_env "statx() only test"

	local mask

	touch $DIR/$tfile
	# Mask supported in stx_attributes by Lustre is
	# STATX_ATTR_IMMUTABLE(0x10) | STATX_ATTR_APPEND(0x20) : (0x30).
	mask=$($STATX -c %p $DIR/$tfile)
	[[ $mask == "30" ]] ||
		error "supported stx_attributes: got '$mask', expected '30'"
	chattr +i $DIR/$tfile || error "chattr +i $DIR/$tfile failed"
	mask=$($STATX -c %r $DIR/$tfile)
	[[ $mask == "10" ]] ||
		error "got immutable flags '$mask', expected '10'"
	chattr -i $DIR/$tfile || error "chattr -i $DIR/$tfile failed"
	mask=$($STATX -c %r $DIR/$tfile)
	[[ $mask == "0" ]] || error "got flags '$mask', expected '0'"
	chattr +a $DIR/$tfile || error "chattr +a $DIR/$tfile failed"
	mask=$($STATX -c %r $DIR/$tfile)
	[[ $mask == "20" ]] || error "got flags '$mask', expected '20'"
	chattr -a $DIR/$tfile || error "chattr -a $DIR/$tfile failed"
	mask=$($STATX -c %r $DIR/$tfile)
	[[ $mask == "0" ]] || error "got flags '$mask', expected '0'"
	chattr +ia $DIR/$tfile || error "chattr +ia $DIR/$tfile failed"
	mask=$($STATX -c %r $DIR/$tfile)
	[[ $mask == "30" ]] || error "got flags '$mask', expected '30'"
	chattr -ia $DIR/$tfile || error "chattr -ia $DIR/$tfile failed"
	mask=$($STATX -c %r $DIR/$tfile)
	[[ $mask == "0" ]] || error "got flags '$mask', expected '0'"
}
run_test 106c "Verify statx attributes mask"

test_107a() { # LU-1031
	dd if=/dev/zero of=$DIR1/$tfile bs=1M count=10
	local gid1=14091995
	local gid2=16022000

	$LFS getstripe $DIR1/$tfile

	multiop_bg_pause $DIR1/$tfile OG${gid1}_g${gid1}c || return 1
	local MULTIPID1=$!
	multiop_bg_pause $DIR2/$tfile O_G${gid2}r10g${gid2}c || return 2
	local MULTIPID2=$!
	kill -USR1 $MULTIPID2
	sleep 2
	if [[ $(ps h -o comm -p $MULTIPID2) == "" ]]; then
		error "First grouplock does not block second one"
	else
		echo "First grouplock blocks second one"
	fi
	kill -USR1 $MULTIPID1
	wait $MULTIPID1
	wait $MULTIPID2
}
run_test 107a "Basic grouplock conflict"

test_107b() {
	dd if=/dev/zero of=$DIR1/$tfile bs=1M count=10
	local gid1=14091995
	local gid2=16022000

	$LFS getstripe $DIR1/$tfile

	multiop_bg_pause $DIR1/$tfile OG${gid1}_g${gid1}c || return 1
	local MULTIPID1=$!
	multiop $DIR2/$tfile Or10c &
	local MULTIPID2=$!
	sleep 2

	if [[ $(ps h -o comm -p $MULTIPID2) == "" ]]; then
		error "Grouplock does not block IO"
	else
		echo "Grouplock blocks IO"
	fi

	multiop $DIR2/$tfile OG${gid2}_g${gid2}c &
	local MULTIPID3=$!
	sleep 2
	if [[ $(ps h -o comm -p $MULTIPID3) == "" ]]; then
		error "First grouplock does not block second one"
	else
		echo "First grouplock blocks second one"
	fi

	kill -USR1 $MULTIPID1
	sleep 2

	if [[ $(ps h -o comm -p $MULTIPID3) == "" ]]; then
		error "Second grouplock thread disappeared"
	fi

	if [[ $(ps h -o comm -p $MULTIPID2) == "" ]]; then
		error "Second grouplock does not block IO"
	else
		echo "Second grouplock blocks IO"
	fi

	kill -USR1 $MULTIPID3
	wait $MULTIPID1
	wait $MULTIPID2
	wait $MULTIPID3
}
run_test 107b "Grouplock is added to the head of waiting list"

test_108a() {
	local offset

	$LFS setstripe -E 1M -c 1 -E -1 $DIR1/$tfile ||
		error "Create $DIR1/$tfile failed"

	dd if=/dev/zero of=$DIR1/$tfile bs=10000 count=1 ||
		error "dd $DIR1/$tfile failed"
	offset=$(lseek_test -d 5000 $DIR2/$tfile)
	[[ $offset == 5000 ]] || error "offset $offset != 5000"

	$TRUNCATE $DIR1/$tfile 2000
	offset=$(lseek_test -l 1000 $DIR2/$tfile)
	[[ $offset == 2000 ]] || error "offset $offset != 2000"

	#define OBD_FAIL_OSC_DELAY_IO 0x414
	$LCTL set_param fail_val=4 fail_loc=0x80000414
	dd if=/dev/zero of=$DIR1/$tfile count=1 bs=8M conv=notrunc oflag=dsync &
	local pid=$!
	sleep 2

	offset=$(lseek_test -l 8000 $DIR2/$tfile)
	wait $pid
	[[ $offset == 8388608 ]] || error "offset $offset != 8388608"
}
run_test 108a "lseek: parallel updates"

# LU-14110
test_109() {
	local i
	local pid1 pid2

	! local_mode ||
		skip "Clients need to be on different nodes than the servers"

	umount_client $MOUNT
	umount_client $MOUNT2

	echo "Starting race between client mount instances (50 iterations):"
	for i in {1..50}; do
		log "Iteration $i"

#define OBD_FAIL_ONCE|OBD_FAIL_LLITE_RACE_MOUNT        0x80001417
		$LCTL set_param -n fail_loc=0x80001417

		mount_client $MOUNT  & pid1=$!
		mount_client $MOUNT2 & pid2=$!
		wait $pid1 || error "Mount $MOUNT fails with $?"
		wait $pid2 || error "Mount $MOUNT2 fails with $?"

		umount_client $MOUNT  & pid1=$!
		umount_client $MOUNT2 & pid2=$!
		wait $pid1 || error "Umount $MOUNT fails with $?"
		wait $pid2 || error "Umount $MOUNT2 fails with $?"

		$LUSTRE_RMMOD || error "Fail to remove lustre modules"
		load_modules
		echo
	done

	mount_client $MOUNT
	mount_client $MOUNT2
}

run_test 109 "Race with several mount instances on 1 node"

test_110() {
	local before=$(date +%s)
	local evict

	mkdir -p $DIR/$tdir
	touch $DIR/$tdir/f1
	touch $DIR/$tfile

	#define OBD_FAIL_PTLRPC_RESEND_RACE	 0x525
	do_facet mds1 lctl set_param fail_loc=0x525 fail_val=3

	# disable last_xid logic by dropping link reply
	ln $DIR/$tdir/f1 $DIR/$tdir/f2 &
	sleep 1

	#define OBD_FAIL_PTLRPC_ENQ_RESEND	0x534
	do_facet mds1 lctl set_param fail_loc=0x534

	# RPC will race with its Resend and the Resend will sleep to let
	# the original lock to get granted & cancelled.
	#
	# AST_SENT is set artificially, so an explicit conflict is not needed
	#
	# The woken up Resend gets a new lock, but client does not wait for it
	stat $DIR/$tfile
	sleep $TIMEOUT
	do_facet mds1 lctl set_param fail_loc=0 fail_val=0

	# Take a conflict to wait long enough to see the eviction
	touch $DIR2/$tfile

	# let the client reconnect
	client_reconnect
	evict=$(do_facet client $LCTL get_param mdc.$FSNAME-MDT*.state |
	  awk -F"[ [,]" '/EVICTED ]$/ { if (mx<$5) {mx=$5;} } END { print mx }')

	[ -z "$evict" ] || [[ $evict -le $before ]] ||
		(do_facet client $LCTL get_param mdc.$FSNAME-MDT*.state;
		    error "eviction happened: $evict before:$before")
}
run_test 110 "do not grant another lock on resend"

test_111() {
	[ $MDSCOUNT -ge 2 ] || skip "needs >= 2 MDTs"
	[[ $(facet_active_host mds1) = $(facet_active_host mds2) ]] ||
		skip "MDT0 and MDT1 should be on the same node"

	mkdir $DIR1/$tdir
	$LFS mkdir -i 0 $DIR1/$tdir/mdt0dir
	$LFS mkdir -i 1 $DIR1/$tdir/mdt1dir

	mkdir $DIR1/$tdir/mdt0dir/foodir
	touch $DIR1/$tdir/mdt0dir/foodir/{file1,file2}

	$MULTIOP $DIR2/$tdir/mdt0dir/foodir/file2 Ow4096_c &
	MULTIOP_PID=$!
	ln $DIR1/$tdir/mdt0dir/foodir/file2 $DIR1/$tdir/mdt1dir/file2

	#define OBD_FAIL_MDS_LINK_RENAME_RACE   0x18a
	do_facet mds1 $LCTL set_param fail_loc=0x8000018a

	ln $DIR1/$tdir/mdt0dir/foodir/file2 $DIR1/$tdir/mdt1dir/file2x &
	sleep 1

	rm $DIR2/$tdir/mdt1dir/file2
	sleep 1

	mv $DIR2/$tdir/mdt0dir/foodir/file1 $DIR2/$tdir/mdt0dir/foodir/file2
	sleep 1

	kill $MULTIOP_PID
	wait
	rm -r $DIR1/$tdir || error "Removing test dir failed"
}
run_test 111 "A racy rename/link an open file should not cause fs corruption"

test_112() {
	(( MDSCOUNT >= 2 )) ||
		skip "We need at least 2 MDTs for this test"

	(( MDS1_VERSION >= $(version_code 2.14.54) )) ||
		skip "Need server version at least 2.14.54"

	local rr
	local count

	rr=$($LCTL get_param -n lmv.*.qos_threshold_rr | head -n1)
	rr=${rr%%%}
	stack_trap "$LCTL set_param lmv.*.qos_threshold_rr=$rr > /dev/null"

	mkdir -p $DIR1/$tdir/s1/s2 || error "mkdir s2 failed"
	$LFS mkdir -i 0 $DIR1/$tdir/s1/s2/s3 || error "mkdir s3 failed"
	$LFS setdirstripe -D -i -1 --max-inherit-rr=0 $DIR1/$tdir/s1/s2/s3 ||
		error "setdirstripe s3 failed"
	$LCTL set_param lmv.*.qos_threshold_rr=90
	mkdir $DIR2/$tdir/s1/s2/s3/d{1..64}
	count=$($LFS getstripe -m $DIR2/$tdir/s1/s2/s3/d* | grep ^0 | wc -l)
	(( count == 64 )) || error "only $count subdirs created on MDT0"

	$LFS setdirstripe -D -i -1 --max-inherit-rr=3 $DIR1/$tdir/s1/s2/s3 ||
		error "setdirstripe s3 failed"
	mkdir $DIR2/$tdir/s1/s2/s3/s{1..64}
	count=$($LFS getstripe -m $DIR2/$tdir/s1/s2/s3/s* | grep ^0 | wc -l)
	(( count == 64 / MDSCOUNT )) || error "$count subdirs created on MDT0"
}
run_test 112 "update max-inherit in default LMV"

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
