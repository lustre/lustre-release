#!/bin/bash

set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test:  3192 4035
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-"14b  14c"}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# Tests that fail on uml
[ "$UML" = "true" ] && EXCEPT="$EXCEPT 7"

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

SIZE=${SIZE:-40960}
CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
CREATETEST=${CREATETEST:-createtest}
GETSTRIPE=${GETSTRIPE:-lfs getstripe}
SETSTRIPE=${SETSTRIPE:-lstripe}
LCTL=${LCTL:-lctl}
MCREATE=${MCREATE:-mcreate}
OPENFILE=${OPENFILE:-openfile}
OPENUNLINK=${OPENUNLINK:-openunlink}
TOEXCL=${TOEXCL:-toexcl}
TRUNCATE=${TRUNCATE:-truncate}
export TMP=${TMP:-/tmp}

if [ $UID -ne 0 ]; then
	RUNAS_ID="$UID"
	RUNAS=""
else
	RUNAS_ID=${RUNAS_ID:-500}
	RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}
fi

SAVE_PWD=$PWD

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

if [ ! -z "$USING_KRB5" ]; then
    $RUNAS krb5_login.sh || exit 1
fi

cleanup() {
	echo -n "cln.."
	grep " $MOUNT2 " /proc/mounts && zconf_umount `hostname` $MOUNT2 ${FORCE}
	cleanupall ${FORCE} > /dev/null || { echo "FAILed to clean up"; exit 20; }
}
CLEANUP=${CLEANUP:-:}

setup() {
	echo -n "mnt.."
	setupall || exit 10
	echo "done"
}
SETUP=${SETUP:-:}

log() {
	echo "$*"
	lctl mark "$*" 2> /dev/null || true
}

trace() {
	log "STARTING: $*"
	strace -o $TMP/$1.strace -ttt $*
	RC=$?
	log "FINISHED: $*: rc $RC"
	return 1
}
TRACE=${TRACE:-""}

LPROC=/proc/fs/lustre

run_one() {
	if ! grep -q $DIR /proc/mounts; then
		$SETUP
	fi
	testnum=$1
	message=$2
	BEFORE=`date +%s`
	log "== test $testnum: $message= `date +%H:%M:%S` ($BEFORE)"
	export TESTNAME=test_$testnum
	export tfile=f${testnum}
	export tdir=d${base}
	test_$1 || error "exit with rc=$?"
	unset TESTNAME
	pass "($((`date +%s` - $BEFORE))s)"
	cd $SAVE_PWD
	$CLEANUP
}

build_test_filter() {
	[ "$ALWAYS_EXCEPT$EXCEPT$SANITYN_EXCEPT" ] && \
	    echo "Skipping tests: `echo $ALWAYS_EXCEPT $EXCEPT $SANITYN_EXCEPT`"

        for O in $ONLY; do
            eval ONLY_${O}=true
        done
        for E in $EXCEPT $ALWAYS_EXCEPT $SANITY_EXCEPT; do
            eval EXCEPT_${E}=true
        done
}

_basetest() {
    echo $*
}

basetest() {
    IFS=abcdefghijklmnopqrstuvwxyz _basetest $1
}

build_test_filter() {
	[ "$ALWAYS_EXCEPT$EXCEPT$SANITYN_EXCEPT" ] && \
	    echo "Skipping tests: `echo $ALWAYS_EXCEPT $EXCEPT $SANITYN_EXCEPT`"

        for O in $ONLY; do
            eval ONLY_${O}=true
        done
        for E in $EXCEPT $ALWAYS_EXCEPT $SANITY_EXCEPT; do
            eval EXCEPT_${E}=true
        done
}

_basetest() {
    echo $*
}

basetest() {
    IFS=abcdefghijklmnopqrstuvwxyz _basetest $1
}

run_test() {
         export base=`basetest $1`
         if [ "$ONLY" ]; then
                 testname=ONLY_$1
                 if [ ${!testname}x != x ]; then
 			run_one $1 "$2"
 			return $?
                 fi
                 testname=ONLY_$base
                 if [ ${!testname}x != x ]; then
                         run_one $1 "$2"
                         return $?
                 fi
                 echo -n "."
                 return 0
 	fi
        testname=EXCEPT_$1
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1"
                 return 0
        fi
        testname=EXCEPT_$base
        if [ ${!testname}x != x ]; then
                 echo "skipping excluded test $1 (base $base)"
                 return 0
        fi
        run_one $1 "$2"
 	return $?
}

[ "$SANITYLOG" ] && rm -f $SANITYLOG || true

error () {
	log "FAIL: $TESTNAME $@"
	if [ "$SANITYLOG" ]; then
		echo "FAIL: $TESTNAME $@" >> $SANITYLOG
	else
		exit 1
	fi
}

pass() {
	echo PASS $@
}

mounted_lustre_filesystems() {
	awk '($3 ~ "lustre" && $1 ~ ":") { print $2 }' /proc/mounts
}
MOUNTED="`mounted_lustre_filesystems`"
if [ -z "$MOUNTED" ]; then
    formatall
    setupall
    mount_client $MOUNT2
    MOUNTED="`mounted_lustre_filesystems`"
    [ -z "$MOUNTED" ] && error "NAME=$NAME not mounted"
    I_MOUNTED=yes
fi
export MOUNT1=`mounted_lustre_filesystems | head -n 1`
[ -z "$MOUNT1" ] && error "NAME=$NAME not mounted once"
export MOUNT2=`mounted_lustre_filesystems | tail -n 1`
[ "$MOUNT1" = "$MOUNT2" ] && error "NAME=$NAME not mounted twice"
[ `mounted_lustre_filesystems | wc -l` -ne 2 ] && \
	error "NAME=$NAME mounted more than twice"

export DIR1=${DIR1:-$MOUNT1}
export DIR2=${DIR2:-$MOUNT2}
[ -z "`echo $DIR1 | grep $MOUNT1`" ] && echo "$DIR1 not in $MOUNT1" && exit 96
[ -z "`echo $DIR2 | grep $MOUNT2`" ] && echo "$DIR2 not in $MOUNT2" && exit 95

rm -rf $DIR1/[df][0-9]* $DIR1/lnk

build_test_filter

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

test_3() {
	( cd $DIR1 ; ln -s this/is/good lnk )
	[ "this/is/good" = "`perl -e 'print readlink("'$DIR2/lnk'");'`" ] || \
		error
}
run_test 3 "symlink on one mtpt, readlink on another ==========="

test_4() {
	multifstat $DIR1/f4 $DIR2/f4
}
run_test 4 "fstat validation on multiple mount points =========="

test_5() {
	mcreate $DIR1/f5
	truncate $DIR2/f5 100
	$CHECKSTAT -t file -s 100 $DIR1/f5 || error
	rm $DIR1/f5
}
run_test 5 "create a file on one mount, truncate it on the other"

test_6() {
	openunlink $DIR1/f6 $DIR2/f6 || error
}
run_test 6 "remove of open file on other node =================="

test_7() {
	opendirunlink $DIR1/d7 $DIR2/d7 || error
}
run_test 7 "remove of open directory on other node ============="

test_8() {
	opendevunlink $DIR1/dev8 $DIR2/dev8 || error
}
run_test 8 "remove of open special file on other node =========="

test_9() {
	MTPT=1
	> $DIR2/f9
	for C in a b c d e f g h i j k l; do
		DIR=`eval echo \\$DIR$MTPT`
		echo -n $C >> $DIR/f9
		[ "$MTPT" -eq 1 ] && MTPT=2 || MTPT=1
	done
	[ "`cat $DIR1/f9`" = "abcdefghijkl" ] || \
		error "`od -a $DIR1/f9` != abcdefghijkl"
}
run_test 9 "append of file with sub-page size on multiple mounts"

test_10a() {
	MTPT=1
	OFFSET=0
	> $DIR2/f10
	for C in a b c d e f g h i j k l; do
		DIR=`eval echo \\$DIR$MTPT`
		echo -n $C | dd of=$DIR/f10 bs=1 seek=$OFFSET count=1
		[ "$MTPT" -eq 1 ] && MTPT=2 || MTPT=1
		OFFSET=`expr $OFFSET + 1`
	done
	[ "`cat $DIR1/f10`" = "abcdefghijkl" ] || \
		error "`od -a $DIR1/f10` != abcdefghijkl"
}
run_test 10a "write of file with sub-page size on multiple mounts "

test_10b() {
	yes "R" | dd of=$DIR1/f10b bs=3k count=1 || error "dd $DIR1"

	truncate $DIR1/f10b 4096 || error "truncate 4096"

	dd if=$DIR2/f10b of=$TMP/f10b-lustre bs=4k count=1 || error "dd $DIR2"

	# create a test file locally to compare
	yes "R" | dd of=$TMP/f10b bs=3k count=1 || error "dd random"
	truncate $TMP/f10b 4096 || error "truncate 4096"
	cmp $TMP/f10b $TMP/f10b-lustre || error "file miscompare"
	rm $TMP/f10b $TMP/f10b-lustre
}
run_test 10b "write of file with sub-page size on multiple mounts "

test_11() {
	mkdir $DIR1/d11
	multiop $DIR1/d11/f O_c &
	MULTIPID=$!
	usleep 200
	cp -p /bin/ls $DIR1/d11/f
	$DIR2/d11/f
	RC=$?
	kill -USR1 $MULTIPID
	wait $MULTIPID || error
	[ $RC -eq 0 ] && error || true
}
run_test 11 "execution of file opened for write should return error ===="

test_12() {
       sh lockorder.sh
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
	mkdir $DIR1/d14
	cp -p /bin/ls $DIR1/d14/ls
	exec 100>> $DIR1/d14/ls
	$DIR2/d14/ls && error || true
	exec 100<&-
}
run_test 14 "execution of file open for write returns -ETXTBSY ="

test_14a() {
        mkdir -p $DIR1/d14
	cp -p `which multiop` $DIR1/d14/multiop || error "cp failed"
        $DIR1/d14/multiop $TMP/test14.junk O_c &
        MULTIPID=$!
        sleep 1
        multiop $DIR2/d14/multiop Oc && error "expected error, got success"
        kill -USR1 $MULTIPID || return 2
        wait $MULTIPID || return 3
        rm $TMP/test14.junk
}
run_test 14a "open(RDWR) of executing file returns -ETXTBSY ===="

test_14b() { # bug 3192
        mkdir -p $DIR1/d14
	cp -p `which multiop` $DIR1/d14/multiop || error "cp failed"
        $DIR1/d14/multiop $TMP/test14.junk O_c &
        MULTIPID=$!
        sleep 1
        truncate $DIR2/d14/multiop 0 && error "expected error, got success"
        kill -USR1 $MULTIPID || return 2
        wait $MULTIPID || return 3
        rm $TMP/test14.junk
}
run_test 14b "truncate of executing file returns -ETXTBSY ======"

test_14c() { # bug 3430
	mkdir -p $DIR1/d14
	cp -p `which multiop` $DIR1/d14/multiop || error "cp failed"
	$DIR1/d14/multiop $TMP/test14.junk O_c &
	MULTIPID=$!
	sleep 1
	cp /etc/hosts $DIR2/d14/multiop && error "expected error, got success"
	kill -USR1 $MULTIPID || return 2
	wait $MULTIPID || return 3
	#cmp `which multiop` $DIR1/d14/multiop || error "binary changed"
	rm $TMP/test14.junk
}
run_test 14c "open(O_TRUNC) of executing file return -ETXTBSY =="

test_15() {	# bug 974 - ENOSPC
	echo "PATH=$PATH"
	sh oos2.sh $MOUNT1 $MOUNT2
}
run_test 15 "test out-of-space with multiple writers ==========="

test_16() {
	fsx -c 50 -p 100 -N 2500 -S 0 $MOUNT1/fsxfile $MOUNT2/fsxfile
}
run_test 16 "2500 iterations of dual-mount fsx ================="

cancel_lru_locks() {
	for d in /proc/fs/lustre/ldlm/namespaces/*-$1-*; do
		echo clear > $d/lru_size
	done
	grep "[0-9]" /proc/fs/lustre/ldlm/namespaces/*-$1-*/lock_unused_count /dev/null
}

test_17() { # bug 3513, 3667
	[ ! -d /proc/fs/lustre/ost ] && echo "skipping OST-only test" && return

	cp /etc/termcap $DIR1/f17
	cancel_lru_locks osc > /dev/null
	#define OBD_FAIL_ONCE|OBD_FAIL_LDLM_CREATE_RESOURCE    0x30a
	echo 0x8000030a > /proc/sys/lustre/fail_loc
	ls -ls $DIR1/f17 | awk '{ print $1,$6 }' > $DIR1/f17-1 & \
	ls -ls $DIR2/f17 | awk '{ print $1,$6 }' > $DIR2/f17-2
	wait
	diff -u $DIR1/f17-1 $DIR2/f17-2 || error "files are different"
}
run_test 17 "resource creation/LVB creation race ==============="

test_18() {
	./mmap_sanity -d $MOUNT1 -m $MOUNT2
	sync; sleep 1; sync
}
run_test 18 "mmap sanity check ================================="

test_19() { # bug3811
	[ -d /proc/fs/lustre/obdfilter ] || return 0

	MAX=`cat /proc/fs/lustre/obdfilter/*/readcache_max_filesize | head -n 1`
	for O in /proc/fs/lustre/obdfilter/*OST*; do
		echo 4096 > $O/readcache_max_filesize
	done
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
	for O in /proc/fs/lustre/obdfilter/*OST*; do
		echo $MAX > $O/readcache_max_filesize
	done
	rm $DIR1/f19b
}
#run_test 19 "test concurrent uncached read races ==============="

test_20() {
	mkdir $DIR1/d20
	cancel_lru_locks osc
	CNT=$((`cat /proc/fs/lustre/llite/*/dump_page_cache | wc -l`))
	multiop $DIR1/f20 Ow8190c
	multiop $DIR2/f20 Oz8194w8190c
	multiop $DIR1/f20 Oz0r8190c
	cancel_lru_locks osc
	CNTD=$((`cat /proc/fs/lustre/llite/*/dump_page_cache | wc -l` - $CNT))
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

JOIN=${JOIN:-"lfs join"}

test_22() { # Bug 9926
	mkdir $DIR1/d21
	dd if=/dev/urandom of=$DIR1/d21/128k bs=1024 count=128
	cp -p $DIR1/d21/128k $DIR1/d21/f_head
	for ((i=0;i<10;i++)); do
		cp -p $DIR1/d21/128k $DIR1/d21/f_tail
		$JOIN $DIR1/d21/f_head $DIR1/d21/f_tail || error "join error"
		$CHECKSTAT -a $DIR1/d21/f_tail || error "tail file exist after join"
	done
	echo aaaaaaaaaaa >> $DIR1/d21/no_joined

	mv $DIR2/d21/f_head $DIR2/
	munlink $DIR2/f_head || error "unlink joined file error"
	cat $DIR2/d21/no_joined || error "cat error"
	rm -rf $DIR2/d21/no_joined || error "unlink normal file error"
}
run_test 22 " After joining in one dir,  open/close unlink file in anther dir" 

test_23() { # Bug 5972
	echo "others should see updated atime while another read" > $DIR1/f23
	
	# clear the lock(mode: LCK_PW) gotten from creating operation
	cancel_lru_locks osc
	
	time1=`date +%s`	
	sleep 2
	
	multiop $DIR1/f23 or20_c &
	MULTIPID=$!

	sleep 2
	time2=`stat -c "%X" $DIR2/f23`

	if (( $time2 <= $time1 )); then
		kill -USR1 $MULTIPID
		error "atime doesn't update among nodes"
	fi

	kill -USR1 $MULTIPID || return 1
	rm -f $DIR1/f23 || error "rm -f $DIR1/f23 failed"
	true
}
run_test 23 " others should see updated atime while another read===="

test_24() {
	touch $DIR1/$tfile
	lfs df || error "lfs df failed"
	lfs df -ih || error "lfs df -ih failed"
	lfs df -h $DIR1 || error "lfs df -h $DIR1 failed"
	lfs df -i $DIR2 || error "lfs df -i $DIR2 failed"
	lfs df $DIR1/$tfile || error "lfs df $DIR1/$tfile failed"
	lfs df -ih $DIR2/$tfile || error "lfs df -ih $DIR2/$tfile failed"
	
	OSC=`lctl dl | awk '/-osc-/ {print $4}' | head -n 1`
	lctl --device %$OSC deactivate
	lfs df -i || error "lfs df -i with deactivated OSC failed"
	lctl --device %$OSC recover
	lfs df || error "lfs df with reactivated OSC failed"
}
run_test 24 "lfs df [-ih] [path] test ========================="

test_25() {
	[ `cat $LPROC/mdc/*-mdc-*/connect_flags | grep -c acl` -lt 2 ] && echo "skipping $TESTNAME (must have acl)" && return

	mkdir $DIR1/d25 || error
	touch $DIR1/d25/f1 || error
	chmod 0755 $DIR1/d25/f1 || error

	$RUNAS checkstat $DIR2/d25/f1 || error
	setfacl -m u:$RUNAS_ID:--- $DIR1/d25 || error
	$RUNAS checkstat $DIR2/d25/f1 && error
	setfacl -m u:$RUNAS_ID:r-x $DIR1/d25 || error
	$RUNAS checkstat $DIR2/d25/f1 || error
	setfacl -m u:$RUNAS_ID:--- $DIR1/d25 || error
	$RUNAS checkstat $DIR2/d25/f1 && error
	setfacl -x u:$RUNAS_ID: $DIR1/d25 || error
	$RUNAS checkstat $DIR2/d25/f1 || error

	rm -rf $DIR1/d25
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

log "cleanup: ======================================================"
rm -rf $DIR1/[df][0-9]* $DIR1/lnk || true
if [ "$I_MOUNTED" = "yes" ]; then
    cleanup
fi

echo '=========================== finished ==============================='
[ -f "$SANITYLOG" ] && cat $SANITYLOG && exit 1 || true

