#!/bin/bash

set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 1557 2366
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-"8   10   "}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] && echo "Skipping tests: $ALWAYS_EXCEPT $EXCEPT"

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
CREATETEST=${CREATETEST:-createtest}
LFIND=${LFIND:-lfind}
LSTRIPE=${LSTRIPE:-lstripe}
LCTL=${LCTL:-lctl}
MCREATE=${MCREATE:-mcreate}
OPENFILE=${OPENFILE:-openfile}
OPENUNLINK=${OPENUNLINK:-openunlink}
TOEXCL=${TOEXCL:-toexcl}
TRUNCATE=${TRUNCATE:-truncate}

if [ $UID -ne 0 ]; then
	RUNAS_ID="$UID"
	RUNAS=""
else
	RUNAS_ID=${RUNAS_ID:-500}
	RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}
fi

export NAME=${NAME:-mount2}

SAVE_PWD=$PWD

clean() {
	echo -n "cln.."
	sh llmountcleanup.sh > /dev/null || exit 20
}
CLEAN=${CLEAN:-clean}

start() {
	echo -n "mnt.."
	sh llrmount.sh > /dev/null || exit 10
	echo "done"
}
START=${START:-start}

log() {
	echo "$*"
	lctl mark "$*" 2> /dev/null || true
}

run_one() {
	if ! mount | grep -q $DIR1; then
		$START
	fi
	log "== test $1: $2"
	export TESTNAME=test_$1
	test_$1 || error "test_$1: exit with rc=$?"
	unset TESTNAME
	pass
	cd $SAVE_PWD
	$CLEAN
}

run_test() {
	for O in $ONLY; do
		if [ "`echo $1 | grep '\<'$O'[a-z]*\>'`" ]; then
			echo ""
			run_one $1 "$2"
			return $?
		else
			echo -n "."
		fi
	done
	for X in $EXCEPT $ALWAYS_EXCEPT; do
		if [ "`echo $1 | grep '\<'$X'[a-z]*\>'`" ]; then
			echo "skipping excluded test $1"
			return 0
		fi
	done
	if [ -z "$ONLY" ]; then
		run_one $1 "$2"
		return $?
	fi
}

[ "$SANITYLOG" ] && rm -f $SANITYLOG || true

error () {
	log "FAIL: $@"
	if [ "$SANITYLOG" ]; then
		echo "FAIL: $TESTNAME $@" >> $SANITYLOG
	else
		exit 1
	fi
}

pass() {
	echo PASS
}

export MOUNT1=`mount| awk '/ lustre/ { print $3 }'| head -1`
export MOUNT2=`mount| awk '/ lustre/ { print $3 }'| tail -1`
[ -z "$MOUNT1" ] && error "NAME=$NAME not mounted once"
[ "$MOUNT1" = "$MOUNT2" ] && error "NAME=$NAME not mounted twice"
[ `mount| awk '/ lustre/ { print $3 }'| wc -l` -ne 2 ] && \
	error "NAME=$NAME mounted more than twice"

export DIR1=${DIR1:-$MOUNT1}
export DIR2=${DIR2:-$MOUNT2}
[ -z "`echo $DIR1 | grep $MOUNT1`" ] && echo "$DIR1 not in $MOUNT1" && exit 96
[ -z "`echo $DIR2 | grep $MOUNT2`" ] && echo "$DIR2 not in $MOUNT2" && exit 95

rm -rf $DIR1/[df][0-9]* $DIR1/lnk

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
run_test 2c "check cached attribute updates on 2 mtpt's root ==="

test_3() {
	( cd $DIR1 ; ln -s this/is/good lnk )
	[ "this/is/good" = "`perl -e 'print readlink("'$DIR2/lnk'");'`" ] || \
		error
}
run_test 3 "symlink on one mtpt, readlink on another ==========="

test_4() {
	./multifstat $DIR1/f4 $DIR2/f4
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
	./openunlink $DIR1/f6 $DIR2/f6 || error
}
run_test 6 "remove of open file on other node =================="

test_7() {
	./opendirunlink $DIR1/d7 $DIR2/d7 || error
}
run_test 7 "remove of open directory on other node ============="

test_8() {
	./opendevunlink $DIR1/dev8 $DIR2/dev8 || error
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
		error "`od -a $DIR1/f10` != abcdefghijkl"
}
run_test 9 "append of file with sub-page size on multiple mounts"

test_10() {
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
run_test 10 "write of file with sub-page size on multiple mounts "

test_11() {
	mkdir $DIR1/d11
	multiop $DIR1/d11/f O_c &
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

log "cleanup: ======================================================"
rm -rf $DIR1/[df][0-9]* $DIR1/lnk || true
echo '=========================== finished ==============================='
[ -f "$SANITYLOG" ] && cat $SANITYLOG && exit 1 || true
