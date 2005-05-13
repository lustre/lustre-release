#!/bin/bash
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-""}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$ALWAYS_EXCEPT$EXCEPT" ] && echo "Skipping tests: $ALWAYS_EXCEPT $EXCEPT"

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH
export SECURITY=${SECURITY:-"null"}

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
MODE=${MODE:mds}

. krb5_env.sh

export NAME=${NAME:-local}

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
	if ! cat /proc/mounts | grep -q $DIR; then
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

rm -rf $DIR/[Rdfs][1-9]*

build_test_filter

echo preparing for tests involving mounts
EXT2_DEV=${EXT2_DEV:-/tmp/SANITY.LOOP}
touch $EXT2_DEV
mke2fs -j -F $EXT2_DEV 8000 > /dev/null

test_1a() {
        rm -fr $DIR/1a0 > /dev/null
	MDS=`find /proc/fs/lustre/mds/* -type d | head -n1 | sed 's/.*\///'`
	[ -z "$MDS" ] && {
	    echo "no MDS available, skipping test"
	    return 0
	}
	count=`find /proc/fs/lustre/mds/* -type d | wc -l`
	[ $count -gt 1 ] && {
	    echo "more than 1 MDS is found, skipping test"
	    return 0
	}

	mkdir $DIR/1a0 || error
	old_last_fid=`cat /proc/fs/lustre/mds/$MDS/last_fid`
	createmany -o $DIR/1a0/f 5000
	new_last_fid=`cat /proc/fs/lustre/mds/$MDS/last_fid`
	
	diff=$(($new_last_fid-$old_last_fid))
	[ $diff -ne 5000 ] && {
	    echo "invalid fid management on $MDS: \
		old $old_last_fid, new $new_last_fid"
	    error
	}
        rm -fr $DIR/1a0 || error
}
run_test 1a " fid correctness (create) ============="

test_1b() {
        rm -fr $DIR/1b0 > /dev/null
	MDS=`find /proc/fs/lustre/mds/* -type d | head -n1 | sed 's/.*\///'`
	[ -z "$MDS" ] && {
	    echo "no MDS available, skipping test"
	    return 0
	}
	count=`find /proc/fs/lustre/mds/* -type d | wc -l`
	[ $count -gt 1 ] && {
	    echo "more than 1 MDS is found, skipping test"
	    return 0
	}

	mkdir $DIR/1b0 || error
	createmany -o $DIR/1b0/f 5000
	old_last_fid=`cat /proc/fs/lustre/mds/$MDS/last_fid`
	rm -fr $DIR/1b0/f
	new_last_fid=`cat /proc/fs/lustre/mds/$MDS/last_fid`
	
	[ $new_last_fid -ne $old_last_fid ] && {
	    echo "invalid fid management on $MDS: \
		old $old_last_fid, new $new_last_fid"
	    error
	}
        rm -fr $DIR/1b0 || error
}
run_test 1b " fid correctness (remove) ============="

TMPDIR=$OLDTMPDIR
TMP=$OLDTMP
HOME=$OLDHOME

log "cleanup: ========================================================"
if [ "`mount | grep ^$NAME`" ]; then
	rm -rf $DIR/[Rdfs][1-9]*
	if [ "$I_MOUNTED" = "yes" ]; then
		sh llmountcleanup.sh || error
	fi
fi

echo "=========================== finished ============================"
[ -f "$SANITYLOG" ] && cat $SANITYLOG && exit 1 || true
