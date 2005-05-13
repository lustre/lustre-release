#!/bin/bash
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-""}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

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
MODE=${MODE:mds}

if [ $UID -ne 0 ]; then
	RUNAS_ID="$UID"
	RUNAS=""
else
	RUNAS_ID=${RUNAS_ID:-500}
	RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}
fi

export NAME=${NAME:-cmobd}

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

lsync() {
        name=$1
        device=`$LCTL device_list | grep " $name " | awk '{print $1}'`
        
        [ -z $device ] && {
                echo "Can't find device $name"
                return 1
        }
        
${LCTL} << EOF
device $device
lsync
EOF
        return $?
}

test_1a() {
        rm -fr $DIR/1a0 > /dev/null

        echo "mkdir $DIR/1a0"
	mkdir $DIR/1a0 || error
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
        
        echo "touch $DIR/1a0/f0"
        touch $DIR/1a0/f0 || error
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
        
        echo "chmod +x $DIR/1a0/f0"
        chmod +x $DIR/1a0/f0 || error
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
        
        echo "mv $DIR/1a0/f0 $DIR/1a0/f01"
        mv $DIR/1a0/f0 $DIR/1a0/f01 || error
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
        
        echo "rm $DIR/1a0/f01"
        rm $DIR/1a0/f01 || error
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
        
        echo "touch $DIR/1a0/f01"
        touch $DIR/1a0/f01 || error
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
        
        echo "ln $DIR/1a0/f01 $DIR/1a0/f01h"
        ln $DIR/1a0/f01 $DIR/1a0/f01h || error
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
        
        echo "ln -s $DIR/1a0/f01 $DIR/1a0/f01s"
        ln -s $DIR/1a0/f01 $DIR/1a0/f01s || error

        rm -fr $DIR/1a0 > /dev/null
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
}
run_test 1a " WB test (lsync after each MD operation)============="

test_1b() {
        echo "mkdir $DIR/1b0"
	mkdir $DIR/1b0 || error
        echo "touch $DIR/1b0/f0"
        touch $DIR/1b0/f0 || error
        echo "chmod +x $DIR/1b0/f0"
        chmod +x $DIR/1b0/f0 || error
        echo "mv $DIR/1b0/f0 $DIR/1b0/f01"
        mv $DIR/1b0/f0 $DIR/1b0/f01 || error
        echo "rm $DIR/1b0/f01"
        rm $DIR/1b0/f01 || error
        echo "touch $DIR/1b0/f01"
        touch $DIR/1b0/f01 || error
        echo "ln $DIR/1b0/f01 $DIR/1b0/f01h"
        ln $DIR/1b0/f01 $DIR/1b0/f01h || error
        echo "ln -s $DIR/1b0/f01 $DIR/1b0/f01s"
        ln -s $DIR/1b0/f01 $DIR/1b0/f01s || error

        rm -fr $DIR/1b0 > /dev/null
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
}
run_test 1b " WB test (lsync after bunch of MD operarions)============="

test_2a() {
        echo "mkdir $DIR/2a0"
	mkdir $DIR/2a0 || error 
        echo "createmany -o $DIR/2a0/f 4000"
	createmany -o $DIR/2a0/f 4000
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
}

test_2b() {
        echo "find $DIR/2a0 -type f -exec rm -f {} \;"
	find $DIR/2a0 -type f -exec rm -f {} \;
	rmdir $DIR/2a0 || error
        echo "cache flush on $NAME"
        lsync $NAME >/dev/null || error
}

[ "x$MODE" = "xlmv" ] && {
run_test 2a " WB test (flush createmany on master LMV) ======================"
run_test 2b " WB test (flush delmany on master LMV) ========================="
}

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
