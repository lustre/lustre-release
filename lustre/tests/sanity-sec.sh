#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
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

if [ $UID -ne 0 ]; then
	RUNAS_ID="$UID"
	RUNAS=""
else
	RUNAS_ID=${RUNAS_ID:-500}
	RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}
fi

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
	if ! mount | grep -q $DIR; then
		$START
	fi
	echo -1 >/proc/sys/portals/debug	
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

OSTCOUNT=`cat /proc/fs/lustre/llite/fs0/lov/numobd`
STRIPECOUNT=`cat /proc/fs/lustre/llite/fs0/lov/stripecount`
STRIPESIZE=`cat /proc/fs/lustre/llite/fs0/lov/stripesize`

build_test_filter

test_0() {
	touch $DIR/f
	$CHECKSTAT -t file $DIR/f || error
	rm $DIR/f
	$CHECKSTAT -a $DIR/f || error
}
run_test 0 "touch .../f ; rm .../f ============================="

mdsdevice(){
        lctl << EOF
        dl
        quit
EOF
}

mynidstr(){
        lctl << EOF
        network tcp
        mynid
        quit
EOF
}

test_1(){
        mdsnum=`mdsdevice|awk ' $3=="mds" {print $1}'`
	if [ ! -z "$mdsnum" ];then
        mynid=`mynidstr|awk '{print $4}'`
        mkdir $DIR/test_0a_dir1
        touch $DIR/test_0a_file1
        ln -s $DIR/test_0a_file1 $DIR/test_0a_filelink1
        chmod 0777 $DIR
        lctl << EOF
        device $mdsnum 
        root_squash 500:500
        root_squash
        quit
EOF
        mkdir $DIR/test_0a_dir2
        touch $DIR/test_0a_file2
        ln -s $DIR/test_0a_file2 $DIR/test_0a_filelink2
        $CHECKSTAT -t dir   -u 500  $DIR/test_0a_dir2 || error
        $CHECKSTAT -t file  -u 500  $DIR/test_0a_file2 || error
        $CHECKSTAT -t link  -u 500  $DIR/test_0a_filelink2 || error
        lctl << EOF
        device $mdsnum 
        root_squash 500:500 $mynid
        root_squash
        quit
EOF
        mkdir $DIR/test_0a_dir3
        touch $DIR/test_0a_file3
        ln -s $DIR/test_0a_file3 $DIR/test_0a_filelink3
        $CHECKSTAT -t dir -u root  $DIR/test_0a_dir3 || error
        $CHECKSTAT -t file -u root $DIR/test_0a_file3 || error
        $CHECKSTAT -t link -u root $DIR/test_0a_filelink3 || error
        lctl << EOF
        device $mdsnum 
        root_squash root:root
        root_squash
        quit
EOF
        mkdir $DIR/test_0a_dir4
        touch $DIR/test_0a_file4
        ln -s $DIR/test_0a_file4 $DIR/test_0a_filelink4
        $CHECKSTAT -t dir -u root  $DIR/test_0a_dir4 || error
        $CHECKSTAT -t file -u root $DIR/test_0a_file4 || error
        $CHECKSTAT -t link -u root $DIR/test_0a_filelink4 || error
        rm -rf $DIR/test_0a*
        chmod 0755 $DIR
	fi
}

run_test 1 "test root_squash ============================"

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
