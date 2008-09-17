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
export SECURITY=${SECURITY:-"null"}

TMP=${TMP:-/tmp}
FSTYPE=${FSTYPE:-ldiskfs}

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

export NAME=${NAME:-lmv}

SAVE_PWD=$PWD

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/lmv.sh}

cleanup() {
	echo -n "cln.."
	cleanupall ${FORCE} $* || { echo "FAILed to clean up"; exit 20; }
}
CLEANUP=${CLEANUP:-:}

setup() {
	echo -n "mnt.."
        load_modules
	setupall || exit 10
	echo "done"
}

SETUP=${SETUP:-:}

log() {
	echo "$*"
	$LCTL mark "$*" 2> /dev/null || true
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
	VERSION_FILE=version
	WANT_VER=$1
	[ ! -f $VERSION_FILE ] && echo "can't find kernel version" && return 1
	GOT_VER=$(lctl get_param $VERSION_FILE | awk '/kernel:/ {print $2}')
	[ $GOT_VER -ge $WANT_VER ] && return 0
	log "test needs at least kernel version $WANT_VER, running $GOT_VER"
	return 1
}

_basetest() {
    echo $*
}

basetest() {
    IFS=abcdefghijklmnopqrstuvwxyz _basetest $1
}

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
	test_${testnum} || error "exit with rc=$?"
	unset TESTNAME
	pass "($((`date +%s` - $BEFORE))s)"
	cd $SAVE_PWD
	$CLEANUP
}

build_test_filter() {
	[ "$ALWAYS_EXCEPT$EXCEPT$SANITY_EXCEPT" ] && \
	    echo "Skipping tests: `echo $ALWAYS_EXCEPT $EXCEPT $SANITY_EXCEPT`"

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

error() { 
	lctl set_param fail_loc=0
	log "FAIL: $TESTNAME $@"
	$LCTL dk $TMP/lustre-log-$TESTNAME.log
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
	MOUNTED="`mounted_lustre_filesystems`"
	[ -z "$MOUNTED" ] && error "NAME=$NAME not mounted"
	I_MOUNTED=yes
fi

[ `echo $MOUNT | wc -w` -gt 1 ] && error "NAME=$NAME mounted more than once"

DIR=${DIR:-$MOUNT}
[ -z "`echo $DIR | grep $MOUNT`" ] && echo "$DIR not in $MOUNT" && exit 99

LOVNAME=`lctl get_param -n llite.*.lov.common_name | tail -n 1`
OSTCOUNT=`lctl get_param -n lov.$LOVNAME.numobd`
STRIPECOUNT=`lctl get_param -n lov.$LOVNAME.stripecount`
STRIPESIZE=`lctl get_param -n lov.$LOVNAME.stripesize`
ORIGFREE=`lctl get_param -n  lov.$LOVNAME.kbytesavail`
MAXFREE=${MAXFREE:-$((200000 * $OSTCOUNT))}
MDS=$(lctl get_param -N mdt.* | grep -v num_refs | tail -n 1 | cut -d"." -f2)

[ -f $DIR/d52a/foo ] && chattr -a $DIR/d52a/foo
[ -f $DIR/d52b/foo ] && chattr -i $DIR/d52b/foo
rm -rf $DIR/[Rdfs][1-9]*

build_test_filter

if [ "${ONLY}" = "MOUNT" ] ; then
	echo "Lustre is up, please go on"
	exit
fi

echo "preparing for tests involving mounts"
EXT2_DEV=${EXT2_DEV:-$TMP/SANITY.LOOP}
touch $EXT2_DEV
mke2fs -j -F $EXT2_DEV 8000 > /dev/null
echo # add a newline after mke2fs.

umask 077

test_0a() {
	mkdir $DIR/0a0 || error 
        for ((i=0;i<5000;i++)); do
                mkdir $DIR/0a0/`uuidgen -t` || error
        done
	rm -rf $DIR/0a0 || error
}
#run_test 0a " create random names ============================="

test_1a() {
	mkdir $DIR/1a0 || error 
	createmany -o $DIR/1a0/f 5000 || error
	rmdir $DIR/1a0 && error
	rm -rf $DIR/1a0 || error
}
run_test 1a " remove splitted dir ============================="

test_1b() {
	mkdir $DIR/1b0 || error
	createmany -o $DIR/1b0/f 5000 || error
	unlinkmany  $DIR/1b0/f 5000 || error
	NUM=`ls $DIR/1b0 | wc -l`
	if [ $NUM -ne 0 ] ; then
		echo "dir must be empty"
		error
	fi

	touch $DIR/1b0/file0 || error
	touch $DIR/1b0/file1 || error
	touch $DIR/1b0/file2 || error

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
	createmany -o $DIR/1b1/f 5000 || error
	unlinkmany $DIR/1b1/f 5000 || error
	NUM=`ls $DIR/1b1 | wc -l`
	if [ $NUM -ne 0 ] ; then
		echo "dir must be empty"
		error
	fi
	touch $DIR/1b1/file0 || error
	touch $DIR/1b1/file1 || error
	touch $DIR/1b1/file2 || error

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
	createmany -o $DIR/2a0/f 5000 || error
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
	createmany -o $DIR/2b1/f 5000 || error
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

#run_test 3c " dir splitting via lfs stripe ============================="

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

test_5a() {
        mount_client $MOUNT2
        # create a cross-ref file
        mkdir -p $MOUNT/$tdir/d1
        mkdir -p $MOUNT2/$tdir/d2
        dd if=/dev/zero of=$MOUNT/$tdir/d1/f1 count=1
        mv $MOUNT2/$tdir/d1/f1 $MOUNT2/$tdir/d2/
        # XXX: a check the file is a cross-ref one is needed.
	cancel_lru_locks mdc
	cancel_lru_locks osc
        dd if=$MOUNT2/$tdir/d2/f1 of=/dev/null
        stat $MOUNT2/$tdir/d2 $MOUNT2/$tdir/d2/f1 > /dev/null
        can1=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk1=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        unlink $MOUNT2/$tdir/d2/f1
        can2=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk2=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        umount $MOUNT2
        [ $can1 -eq $can2 ] && error "It does not look like a cross-ref file."
        [ $[$can1+1] -eq $can2 ] || error $[$[$can2-$can1]] "cancel RPC occured."
        [ $blk1 -eq $blk2 ] || error $[$[$blk2-$blk1]] "blocking RPC occured."
}
run_test 5a "Early Lock Cancel: cross-ref unlink"

test_5b() {
        mount_client $MOUNT2
        # create a cross-ref file
        mkdir -p $MOUNT/$tdir/d1
        mkdir -p $MOUNT2/$tdir/d2
        dd if=/dev/zero of=$MOUNT/$tdir/d1/f1 count=1
	cancel_lru_locks mdc
	cancel_lru_locks osc
        dd if=$MOUNT2/$tdir/d1/f1 of=/dev/null
        stat $MOUNT2/$tdir/d1/f1 $MOUNT2/$tdir/d2 > /dev/null
        can1=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk1=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        ln $MOUNT2/$tdir/d1/f1 $MOUNT2/$tdir/d2/f2
        can2=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk2=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        umount $MOUNT2
        [ $can1 -eq $can2 ] && error "It does not look like a cross-ref file."
        [ $[$can1+1] -eq $can2 ] || error $[$[$can2-$can1]] "cancel RPC occured."
        [ $blk1 -eq $blk2 ] || error $[$[$blk2-$blk1]] "blocking RPC occured."
}
run_test 5b "Early Lock Cancel: cross-ref link"

TMPDIR=$OLDTMPDIR
TMP=$OLDTMP
HOME=$OLDHOME

log "cleanup: ======================================================"
if [ "`mount | grep ^$NAME`" ]; then
    rm -rf $DIR/[Rdfs][1-9]*
fi
if [ "$I_MOUNTED" = "yes" ]; then
    cleanupall -f || error "cleanup failed"
fi

echo '=========================== finished ==============================='
[ -f "$SANITYLOG" ] && cat $SANITYLOG && exit 1 || true
