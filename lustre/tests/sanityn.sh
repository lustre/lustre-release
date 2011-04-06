#!/bin/bash

set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 3192 15528/3811 16929 9977 15528/11549 18080
ALWAYS_EXCEPT="                14b  19         22    28   29          35    $SANITYN_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# bug number for skipped test:                                                    12652 12652
grep -q 'Enterprise Server 10' /etc/SuSE-release && ALWAYS_EXCEPT="$ALWAYS_EXCEPT 11    14" || true

# Tests that fail on uml
[ "$UML" = "true" ] && EXCEPT="$EXCEPT 7"

# It will be ported soon.
EXCEPT="$EXCEPT 22"

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

SIZE=${SIZE:-40960}
CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
GETSTRIPE=${GETSTRIPE:-lfs getstripe}
SETSTRIPE=${SETSTRIPE:-lstripe}
MCREATE=${MCREATE:-mcreate}
OPENFILE=${OPENFILE:-openfile}
OPENUNLINK=${OPENUNLINK:-openunlink}
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

[ "$SLOW" = "no" ] && EXCEPT_SLOW="12 16 23 33a"

FAIL_ON_ERROR=false

SETUP=${SETUP:-:}
TRACE=${TRACE:-""}

check_and_setup_lustre

LOVNAME=`lctl get_param -n llite.*.lov.common_name | tail -n 1`
OSTCOUNT=`lctl get_param -n lov.$LOVNAME.numobd`

assert_DIR
rm -rf $DIR1/[df][0-9]* $DIR1/lnk

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

test_3() {
	( cd $DIR1 ; ln -s this/is/good $tfile )
	[ "this/is/good" = "`perl -e 'print readlink("'$DIR2/$tfile'");'`" ] ||
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
	mkdir $DIR1/d11
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
       rm -rf $DIR1/d13
       mkdir $DIR1/d13 || error
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
	mkdir -p $DIR1/$tdir
	cp -p /bin/ls $DIR1/$tdir/$tfile
	multiop_bg_pause $DIR1/$tdir/$tfile Ow_c || return 1
	MULTIPID=$!

	$DIR2/$tdir/$tfile && error || true
	kill -USR1 $MULTIPID
	wait $MULTIPID || return 2
}
run_test 14 "execution of file open for write returns -ETXTBSY ="

test_14a() {
        mkdir -p $DIR1/d14
	cp -p `which multiop` $DIR1/d14/multiop || error "cp failed"
        MULTIOP_PROG=$DIR1/d14/multiop multiop_bg_pause $TMP/test14.junk O_c || return 1
        MULTIOP_PID=$!
        multiop $DIR2/d14/multiop Oc && error "expected error, got success"
        kill -USR1 $MULTIOP_PID || return 2
        wait $MULTIOP_PID || return 3
        rm $TMP/test14.junk $DIR1/d14/multiop || error "removing multiop"
}
run_test 14a "open(RDWR) of executing file returns -ETXTBSY ===="

test_14b() { # bug 3192, 7040
        mkdir -p $DIR1/d14
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
	mkdir -p $DIR1/d14
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
	mkdir -p $DIR1/d14
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
	grant_error=`dmesg | grep "> available"`
	[ -z "$grant_error" ] || error "$grant_error"
}
run_test 15 "test out-of-space with multiple writers ==========="

test_16() {
	rm -f $MOUNT1/fsxfile
	lfs setstripe $MOUNT1/fsxfile -c -1 # b=10919
	fsx -c 50 -p 100 -N 2500 -l $((SIZE * 256)) -S 0 $MOUNT1/fsxfile $MOUNT2/fsxfile
}
run_test 16 "2500 iterations of dual-mount fsx ================="

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
	$LUSTRE/tests/mmap_sanity -d $MOUNT1 -m $MOUNT2
	sync; sleep 1; sync
}
run_test 18 "mmap sanity check ================================="

test_19() { # bug3811
	[ -d /proc/fs/lustre/obdfilter ] || return 0

	MAX=`lctl get_param -n obdfilter.*.readcache_max_filesize | head -n 1`
	lctl set_param -n obdfilter.*OST*.readcache_max_filesize=4096
	dd if=/dev/urandom of=$TMP/f19b bs=512k count=32
	SUM=`cksum $TMP/f19b | cut -d" " -f 1,2`
	cp $TMP/f19b $DIR1/f19b
	for i in `seq 1 20`; do
		[ $((i % 5)) -eq 0 ] && log "test_18 loop $i"
		cancel_lru_locks osc > /dev/null
		cksum $DIR1/f19b | cut -d" " -f 1,2 > $TMP/sum1 & \
		cksum $DIR2/f19b | cut -d" " -f 1,2 > $TMP/sum2
		wait
		[ "`cat $TMP/sum1`" = "$SUM" ] || \
			error "$DIR1/f19b `cat $TMP/sum1` != $SUM"
		[ "`cat $TMP/sum2`" = "$SUM" ] || \
			error "$DIR2/f19b `cat $TMP/sum2` != $SUM"
	done
	lctl set_param -n obdfilter.*OST*.readcache_max_filesize=$MAX
	rm $DIR1/f19b
}
run_test 19 "test concurrent uncached read races ==============="

test_20() {
	mkdir $DIR1/d20
	cancel_lru_locks osc
	CNT=$((`lctl get_param -n llite.*.dump_page_cache | wc -l`))
	multiop $DIR1/f20 Ow8190c
	multiop $DIR2/f20 Oz8194w8190c
	multiop $DIR1/f20 Oz0r8190c
	cancel_lru_locks osc
	CNTD=$((`lctl get_param -n llite.*.dump_page_cache | wc -l` - $CNT))
	[ $CNTD -gt 0 ] && \
	    error $CNTD" page left in cache after lock cancel" || true
}
run_test 20 "test extra readahead page left in cache ===="

cleanup_21() {
	trap 0
	umount $DIR1/d21
}

test_21() { # Bug 5907
	mkdir $DIR1/d21
	mount /etc $DIR1/d21 --bind || error "mount failed" # Poor man's mount.
	trap cleanup_21 EXIT
	rmdir -v $DIR1/d21 && error "Removed mounted directory"
	rmdir -v $DIR2/d21 && echo "Removed mounted directory from another mountpoint, needs to be fixed"
	test -d $DIR1/d21 || error "Mounted directory disappeared"
	cleanup_21
	test -d $DIR2/d21 || test -d $DIR1/d21 && error "Removed dir still visible after umount"
	true
}
run_test 21 " Try to remove mountpoint on another dir ===="

test_23() { # Bug 5972
	echo "others should see updated atime while another read" > $DIR1/f23
	
	# clear the lock(mode: LCK_PW) gotten from creating operation
	cancel_lru_locks osc
	
	time1=`date +%s`	
	#MAX_ATIME_DIFF 60, we update atime only if older than 60 seconds
	sleep 61
	
	multiop_bg_pause $DIR1/f23 or20_c || return 1
        # with SOM and opencache enabled, we need to close a file and cancel
        # open lock to get atime propogated to MDS
        kill -USR1 $!
        cancel_lru_locks mdc

	time2=`stat -c "%X" $DIR2/f23`

	if (( $time2 <= $time1 )); then
		error "atime doesn't update among nodes"
	fi

	rm -f $DIR1/f23 || error "rm -f $DIR1/f23 failed"
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
	lctl --device %$OSC recover
	lfs df || error "lfs df with reactivated OSC failed"
}
run_test 24a "lfs df [-ih] [path] test ========================="

test_24b() {
	touch $DIR1/$tfile
	fsnum=`lfs df | grep -c "filesystem summary:"`
	[ $fsnum -eq 2 ] || error "lfs df shows $fsnum != 2 filesystems."
}
run_test 24b "lfs df should show both filesystems ==============="

test_25() {
	[ `lctl get_param -n mdc.*-mdc-*.connect_flags | grep -c acl` -lt 2 ] && \
	    skip "must have acl, skipping" && return

	mkdir -p $DIR1/$tdir
	touch $DIR1/$tdir/f1 || error "touch $DIR1/$tdir/f1"
	chmod 0755 $DIR1/$tdir/f1 || error "chmod 0755 $DIR1/$tdir/f1"

	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 || error "checkstat $DIR2/$tdir/f1 #1"
	setfacl -m u:$RUNAS_ID:--- -m g:$RUNAS_GID:--- $DIR1/$tdir || error "setfacl $DIR2/$tdir #1"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 && error "checkstat $DIR2/$tdir/f1 #2"
	setfacl -m u:$RUNAS_ID:r-x -m g:$RUNAS_GID:r-x $DIR1/$tdir || error "setfacl $DIR2/$tdir #2"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 || error "checkstat $DIR2/$tdir/f1 #3"
	setfacl -m u:$RUNAS_ID:--- -m g:$RUNAS_GID:--- $DIR1/$tdir || error "setfacl $DIR2/$tdir #3"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 && error "checkstat $DIR2/$tdir/f1 #4"
	setfacl -x u:$RUNAS_ID: -x g:$RUNAS_GID: $DIR1/$tdir || error "setfacl $DIR2/$tdir #4"
	$RUNAS $CHECKSTAT $DIR2/$tdir/f1 || error "checkstat $DIR2/$tdir/f1 #5"

	rm -rf $DIR1/$tdir
}
run_test 25 "change ACL on one mountpoint be seen on another ==="

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
	tOST=`$LCTL dl | | awk '/-osc-|OSC.*MNT/ { print $4 }' | head -1`

	lfs setstripe $DIR1/$tfile -s 1048576 -i 0 -c 2
	tOBJID=`lfs getstripe $DIR1/$tfile |grep "^[[:space:]]\+1" |awk '{print $2}'`
	dd if=/dev/zero of=$DIR1/$tfile bs=1024k count=2

	$LCTL <<-EOF
		newdev
		attach echo_client ECHO_osc1 $ECHO_UUID
		setup $tOST
	EOF

	tECHOID=`$LCTL dl | grep $ECHO_UUID | awk '{print $1}'`
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

test_30() { #bug #11110
    mkdir -p $DIR1/$tdir
    cp -f /bin/bash $DIR1/$tdir/bash
    /bin/sh -c 'sleep 1; rm -f $DIR2/$tdir/bash; cp /bin/bash $DIR2/$tdir' &
    err=$($DIR1/$tdir/bash -c 'sleep 2; openfile -f O_RDONLY /proc/$$/exe >& /dev/null; echo $?')
    wait
    [ $err -ne 116 ] && error_ignore 12900 "return code ($err) != -ESTALE" && return
    true
}

run_test 30 "recreate file race ========="

test_31a() {
        mkdir -p $DIR1/$tdir || error "Creating dir $DIR1/$tdir"
        writes=`LANG=C dd if=/dev/zero of=$DIR/$tdir/$tfile count=1 2>&1 |
                awk 'BEGIN { FS="+" } /out/ {print $1}'`
        #define OBD_FAIL_LDLM_CANCEL_BL_CB_RACE   0x314
        lctl set_param fail_loc=0x314
        reads=`LANG=C dd if=$DIR2/$tdir/$tfile of=/dev/null 2>&1 |
               awk 'BEGIN { FS="+" } /in/ {print $1}'`
        [ $reads -eq $writes ] || error "read" $reads "blocks, must be" $writes
}
run_test 31a "voluntary cancel / blocking ast race=============="

test_31b() {
        remote_ost || { skip "local OST" && return 0; }
        remote_ost_nodsh && skip "remote OST w/o dsh" && return 0
        mkdir -p $DIR1/$tdir || error "Creating dir $DIR1/$tdir"
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
        local p="$TMP/sanityN-$TESTNAME.parameters"
        save_lustre_params $HOSTNAME osc.*.lockless_truncate > $p
        cancel_lru_locks osc
        enable_lockless_truncate 1
        rm -f $DIR1/$tfile
        lfs setstripe -c -1 $DIR1/$tfile
        dd if=/dev/zero of=$DIR1/$tfile count=10 bs=1M > /dev/null 2>&1
        clear_osc_stats

        log "checking cached lockless truncate"
        $TRUNCATE $DIR1/$tfile 8000000
        $CHECKSTAT -s 8000000 $DIR2/$tfile || error "wrong file size"
        [ $(calc_osc_stats lockless_truncate) -eq 0 ] ||
                error "lockless truncate doesn't use cached locks"

        log "checking not cached lockless truncate"
        $TRUNCATE $DIR2/$tfile 5000000
        $CHECKSTAT -s 5000000 $DIR1/$tfile || error "wrong file size"
        [ $(calc_osc_stats lockless_truncate) -ne 0 ] ||
                error "not cached trancate isn't lockless"

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
        local p="$TMP/sanityN-$TESTNAME.parameters"
        save_lustre_params $HOSTNAME "osc.*.contention_seconds" > $p
        for node in $(osts_nodes); do
                save_lustre_params $node "ldlm.namespaces.filter-*.max_nolock_bytes" >> $p
                save_lustre_params $node "ldlm.namespaces.filter-*.contended_locks" >> $p
                save_lustre_params $node "ldlm.namespaces.filter-*.contention_seconds" >> $p
        done
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
        dev=$(basename $(do_facet $mds lctl get_param -n osd*.${!varsvc}.mntdev))
        val=$(do_facet $mds "procfile=/proc/fs/jbd/$dev/info;
[ -f \\\$procfile ] || procfile=/proc/fs/jbd2/$dev/info;
[ -f \\\$procfile ] || procfile=/proc/fs/jbd2/${dev}\:\\\*/info;
cat \\\$procfile | head -1;")
        val=${val%% *};
        stat=$(( stat + val))
    done
    echo $stat
}

# commit on sharing tests
test_33a() {
    remote_mds_nodsh && skip "remote MDS with nodsh" && return

    [ -n "$CLIENTS" ] || { skip "Need two or more clients" && return 0; }
    [ $CLIENTCOUNT -ge 2 ] || \
        { skip "Need two or more clients, have $CLIENTCOUNT" && return 0; }

    local nfiles=${TEST33_NFILES:-10000}
    local param_file=$TMP/$tfile-params

    save_lustre_params $(comma_list $(mdts_nodes)) "mdt.*.commit_on_sharing" > $param_file

    local COS
    local jbdold
    local jbdnew
    local jbd

    for COS in 0 1; do
        do_facet $SINGLEMDS lctl set_param mdt.*.commit_on_sharing=$COS
        avgjbd=0
        avgtime=0
        for i in 1 2 3; do
            do_nodes $CLIENT1,$CLIENT2 "mkdir -p $DIR1/$tdir-\\\$(hostname)-$i"

            jbdold=$(print_jbd_stat)
            echo "=== START createmany old: $jbdold transaction"
            local elapsed=$(do_and_time "do_nodes $CLIENT1,$CLIENT2 createmany -o $DIR1/$tdir-\\\$(hostname)-$i/f- -r $DIR2/$tdir-\\\$(hostname)-$i/f- $nfiles > /dev/null 2>&1")
            jbdnew=$(print_jbd_stat)
            jbd=$(( jbdnew - jbdold ))
            echo "=== END   createmany new: $jbdnew transaction :  $jbd transactions  nfiles $nfiles time $elapsed COS=$COS"
            avgjbd=$(( avgjbd + jbd ))
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

# End commit on sharing tests

get_ost_lock_timeouts() {
    local nodes=${1:-$(comma_list $(osts_nodes))}

    local locks=$(do_nodes $nodes \
        "lctl get_param -n ldlm.namespaces.filter-*.lock_timeouts" | calc_sum)

    echo $locks
}

test_34() { #16129
        local OPER
        local lock_in
        local lock_out
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
}
run_test 34 "no lock timeout under IO"

test_35() { # bug 17645
        local generation=[]
        local count=0
        for imp in /proc/fs/lustre/mdc/$FSNAME-MDT*-mdc-*; do
            g=$(awk '/generation/{print $2}' $imp/import)
            generation[count]=$g
            let count=count+1
        done

        mkdir -p $MOUNT1/$tfile
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
        for imp in /proc/fs/lustre/mdc/$FSNAME-MDT*-mdc-*; do
            g=$(awk '/generation/{print $2}' $imp/import)
            if ! test "$g" -eq "${generation[count]}"; then
                error "Eviction happened on import $(basename $imp)"
            fi
            let count=count+1
        done
}
run_test 35 "-EINTR cp_ast vs. bl_ast race does not evict client"

test_36() { #bug 16417
    local SIZE
    local SIZE_B
    local i

    mkdir -p $DIR1/$tdir
    $LFS setstripe -c -1 $DIR1/$tdir
    i=0
    SIZE=50
    let SIZE_B=SIZE*1024*1024

    while [ $i -le 10 ]; do
        lctl mark "start test"
        local before=$($LFS df | awk '{if ($1 ~/^filesystem/) {print $5; exit} }')
        dd if=/dev/zero of=$DIR1/$tdir/file000 bs=1M count=$SIZE
        sync
        sleep 1
        local after_dd=$($LFS df | awk '{if ($1 ~/^filesystem/) {print $5; exit} }')
        multiop_bg_pause $DIR2/$tdir/file000 O_r${SIZE_B}c || return 3
        read_pid=$!
        rm -f $DIR1/$tdir/file000
        kill -USR1 $read_pid
        wait $read_pid
        sleep 1
        local after=$($LFS df | awk '{if ($1 ~/^filesystem/) {print $5; exit} }')
        echo "*** cycle($i) *** before($before):after_dd($after_dd):after($after)"
        # this free space! not used
        if [ $after_dd -ge $after ]; then
            error "space leaked"
            return 1;
        fi
        let i=i+1
            done
}
run_test 36 "handle ESTALE/open-unlink corectly"

test_37() { # bug 18695
	mkdir -p $DIR1/$tdir
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
	multiop $DIR1/$tfile oO_CREAT:O_RDWR:c &
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
	multiop $DIR1/$tfile oO_CREAT:O_RDWR:c &
	PID1=$!
	sleep 1
	multiop $DIR2/$tfile oO_CREAT:O_EXCL:c && error "create must fail"
	check_pdo_conflict $PID1 && { wait $PID1; error "create isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 41b "pdirops: create vs create =============="

test_41c() {
	touch $DIR1/$tfile-2
#define OBD_FAIL_ONCE|OBD_FAIL_MDS_PDO_LOCK    0x145
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000145
	multiop $DIR1/$tfile oO_CREAT:O_RDWR:c &
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
	multiop $DIR1/$tfile oO_CREAT:O_RDWR:c &
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
	multiop $DIR1/$tfile oO_CREAT:O_RDWR:c &
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
	multiop $DIR1/$tfile oO_CREAT:O_RDWR:c &
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
	multiop $DIR1/$tfile oO_CREAT:O_RDWR:c &
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
	multiop $DIR1/$tfile oO_CREAT:O_RDWR:c &
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
	multiop $DIR2/$tfile oO_CREAT:O_EXCL:c && error "create must fail"
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
	multiop $DIR2/$tfile oO_CREAT:O_EXCL:c || error "create must succeed"
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
	multiop $DIR2/$tfile oO_CREAT:O_EXCL:c && error "create must fail"
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
	multiop $DIR2/$tfile oO_CREAT:O_EXCL:c || error "create must succeed"
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
	stat $DIR2/$tfile > /dev/null && "stat must fail"
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
	multiop $DIR2/$tfile oO_CREAT:O_EXCL:c && error "create must fail"
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
	check_pdo_conflict $PID1 && { wait $PID1; error "readdir isn't blocked"; }
	rm -r $DIR1/*
	return 0
}
run_test 46h "pdirops: link vs readdir =============="

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

log "cleanup: ======================================================"

[ "$(mount | grep $MOUNT2)" ] && umount $MOUNT2

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
exit_status
