#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 2108
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-""}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!
#case `uname -r` in
#2.6.*) ALWAYS_EXCEPT="$ALWAYS_EXCEPT 54c 55" # bug 3117
#esac

[ "$ALWAYS_EXCEPT$EXCEPT" ] && echo "Skipping tests: $ALWAYS_EXCEPT $EXCEPT"

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

TMP=${TMP:-/tmp}
FSTYPE=${FSTYPE:-ext3}

CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
CREATETEST=${CREATETEST:-createtest}
LFS=${LFS:-lfs}
LSTRIPE=${LSTRIPE:-"$LFS setstripe"}
LFIND=${LFIND:-"$LFS find"}
LVERIFY=${LVERIFY:-ll_dirstripe_verify}
LCTL=${LCTL:-lctl}
MCREATE=${MCREATE:-mcreate}
OPENFILE=${OPENFILE:-openfile}
OPENUNLINK=${OPENUNLINK:-openunlink}
TOEXCL=${TOEXCL:-toexcl}
TRUNCATE=${TRUNCATE:-truncate}
MUNLINK=${MUNLINK:-munlink}
SOCKETSERVER=${SOCKETSERVER:-socketserver}
SOCKETCLIENT=${SOCKETCLIENT:-socketclient}
IOPENTEST1=${IOPENTEST1:-iopentest1}
IOPENTEST2=${IOPENTEST2:-iopentest2}
PTLDEBUG=${PTLDEBUG:-0}

if [ $UID -ne 0 ]; then
	RUNAS_ID="$UID"
	RUNAS=""
else
	RUNAS_ID=${RUNAS_ID:-500}
	RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}
fi

export NAME=${NAME:-lmv}

SAVE_PWD=$PWD

clean() {
	echo -n "cln.."
	sh llmountcleanup.sh > /dev/null || exit 20
	I_MOUNTED=no
}
CLEAN=${CLEAN:-clean}

start() {
	echo -n "mnt.."
	sh llrmount.sh > /dev/null || exit 10
	I_MOUNTED=yes
	echo "done"
}
START=${START:-start}

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

check_kernel_version() {
	VERSION_FILE=/proc/fs/lustre/kernel_version
	WANT_VER=$1
	[ ! -f $VERSION_FILE ] && echo "can't find kernel version" && return 1
	GOT_VER=`cat $VERSION_FILE`
	[ $GOT_VER -ge $WANT_VER ] && return 0
	log "test needs at least kernel version $WANT_VER, running $GOT_VER"
	return 1
}

run_one() {
	if ! mount | grep -q $DIR; then
		$START
	fi
	echo $PTLDEBUG >/proc/sys/portals/debug	
	log "== test $1: $2"
	export TESTNAME=test_$1
	test_$1 || error "test_$1: exit with rc=$?"
	unset TESTNAME
	pass
	cd $SAVE_PWD
	$CLEAN
}

build_test_filter() {
        for O in $ONLY; do
            eval ONLY_${O}=true
        done
        for E in $EXCEPT $ALWAYS_EXCEPT; do
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
         base=`basetest $1`
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

error() { 
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

MOUNT="`mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
if [ -z "$MOUNT" ]; then
	sh llmount.sh
	MOUNT="`mount | awk '/^'$NAME' .* lustre_lite / { print $3 }'`"
	[ -z "$MOUNT" ] && error "NAME=$NAME not mounted"
	I_MOUNTED=yes
fi

[ `echo $MOUNT | wc -w` -gt 1 ] && error "NAME=$NAME mounted more than once"

DIR=${DIR:-$MOUNT}
[ -z "`echo $DIR | grep $MOUNT`" ] && echo "$DIR not in $MOUNT" && exit 99

#LOVNAME=`cat /proc/fs/lustre/llite/fs0/lov/common_name`
#OSTCOUNT=`cat /proc/fs/lustre/lov/$LOVNAME/numobd`
#STRIPECOUNT=`cat /proc/fs/lustre/lov/$LOVNAME/stripecount`
#STRIPESIZE=`cat /proc/fs/lustre/lov/$LOVNAME/stripesize`

[ -f $DIR/d52a/foo ] && chattr -a $DIR/d52a/foo
[ -f $DIR/d52b/foo ] && chattr -i $DIR/d52b/foo
rm -rf $DIR/[Rdfs][1-9]*

build_test_filter

echo preparing for tests involving mounts
EXT2_DEV=${EXT2_DEV:-/tmp/SANITY.LOOP}
touch $EXT2_DEV
mke2fs -j -F $EXT2_DEV 8000 > /dev/null

test_1a() {
	mkdir $DIR/1a0 || error 
	createmany -o $DIR/1a0/f 4000
	rmdir $DIR/1a0 && error
	rm -rf $DIR/1a0 || error
}
run_test 1a " remove splitted dir ============================="

test_1b() {
	mkdir $DIR/1b0 || error
	createmany -o $DIR/1b0/f 4000
	find $DIR/1b0 -type f | xargs rm -f
	NUM=`ls $DIR/1b0 | wc -l`
	if [ $NUM -ne 0 ] ; then
		echo "dir must be empty"
		error
	fi
	touch $DIR/1b0/file0
	touch $DIR/1b0/file1
	touch $DIR/1b0/file2

	echo "3 files left"
	rmdir $DIR/1b0 && error
	rm -f $DIR/1b0/file0

	echo "2 files left"
	rmdir $DIR/1b0 && error
	rm -f $DIR/1b0/file1

	echo "1 files left"
	rmdir $DIR/1b0 && error
	rm -f $DIR/1b0/file2

	echo "0 files left"
	rmdir $DIR/1b0 || error
}
run_test 1b " remove splitted dir ============================="

test_1c() {
	mkdir $DIR/1b1 || error
	createmany -o $DIR/1b1/f 4000
	find $DIR/1b1 -type f | xargs rm -f
	NUM=`ls $DIR/1b1 | wc -l`
	if [ $NUM -ne 0 ] ; then
		echo "dir must be empty"
		error
	fi
	touch $DIR/1b1/file0
	touch $DIR/1b1/file1
	touch $DIR/1b1/file2

	ls $DIR/1b1/
	log "3 files left"
	rmdir $DIR/1b1 && error
	rm -f $DIR/1b1/file0

	ls $DIR/1b1/
	log "2 files left"
	rmdir $DIR/1b1 && error
	rm -f $DIR/1b1/file1

	ls $DIR/1b1/
	log "1 files left"
	rmdir $DIR/1b1 && error
	rm -f $DIR/1b1/file2

	ls $DIR/1b1/
	log "0 files left"
	rmdir $DIR/1b1 || error
}
run_test 1c " remove splitted cross-node dir ============================="

test_2a() {
	mkdir $DIR/2a0 || error 
	createmany -o $DIR/2a0/f 5000
	NUM=`ls $DIR/2a0 | wc -l`
	echo "found $NUM files"
	if [ $NUM -ne 5000 ]; then
		echo "wrong number of files: $NUM"
		error
	fi
	rm -rf $DIR/2a0 || error
}
run_test 2a " list splitted dir ============================="

test_2b() {
	mkdir $DIR/2b1 || error 
	createmany -o $DIR/2b1/f 5000
	$CLEAN
	$START
	statmany -l $DIR/2b1/f 5000 5000 || error
	statmany -s $DIR/2b1/f 5000 5000 || error
	rm -rf $DIR/2b1 || error
}
run_test 2b " list splitted dir after remount ============================="

test_3a() {
	mkdir $DIR/3a0 || error
	for i in `seq 100`; do
		mkdir $DIR/3a0/d${i} || error
	done
	createmany -o $DIR/3a0/f 5000 || error
	rm -rf $DIR/3a0 || error
}
run_test 3a " dir splitting with cross-ref ============================="

test_3b() {
	mkdir $DIR/3b1 || error
	createmany -m $DIR/3b1/f 5000 || error
	rm -rf $DIR/3b1 || error
}
run_test 3b " dir splitting via createmany -m ============================="

test_3c() {
	mkdir $DIR/3c1 || error
	echo "MDS nodes: $MDSCOUNT"
	for j in `seq 3`; do
		for i in `seq 10`; do
			$LFS dirstripe $DIR/3c1/d-${j}-${i} $j || error
			createmany -m $DIR/3c1/d-${j}-${i}/m 200 || error
			createmany -o $DIR/3c1/d-${j}-${i}/o 200 || error
		done
	done
	rm -rf $DIR/3c1 || error
}

run_test 3c " dir splitting via lfs stripe ============================="

test_4a() {
	let rr=0
	while let "rr < 33000"; do
		if let "rr % 2000 == 0"; then
			echo "$rr"
		fi
		mkdir $DIR/4a1 || error
		rm -rf $DIR/4a1
		let "rr = rr + 1"
	done
}

## this test is very time-consuming, don't run it by default
#run_test 4a " FIDS/ nlink overflow test  ============================="


TMPDIR=$OLDTMPDIR
TMP=$OLDTMP
HOME=$OLDHOME

log "cleanup: ======================================================"
if [ "`mount | grep ^$NAME`" ]; then
	rm -rf $DIR/[Rdfs][1-9]*
	if [ "$I_MOUNTED" = "yes" ]; then
		sh llmountcleanup.sh || error
	fi
fi

echo '=========================== finished ==============================='
[ -f "$SANITYLOG" ] && cat $SANITYLOG && exit 1 || true
