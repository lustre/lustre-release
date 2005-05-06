#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-""}
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

. krb5_env.sh

if [ $UID -ne 0 ]; then
	RUNAS_ID="$UID"
	RUNAS=""
else
	RUNAS_ID=${RUNAS_ID:-500}
	RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}
fi

if [ `using_krb5_sec $SECURITY` == 'y' ] ; then
    start_krb5_kdc || exit 1
    if [ $RUNAS_ID -ne $UID ]; then
        $RUNAS ./krb5_refresh_cache.sh || exit 2
    fi
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
mke2fs -j -F $EXT2_DEV 8000 >/dev/null 2>&1

find_free_loop() {
    local LOOP_DEV=""
    test -b /dev/loop0 && 
	base="/dev/loop" || base="/dev/loop/"

    for ((i=0;i<256;i++)); do
	test -b $base$i || continue
	
	losetup $base$i >/dev/null 2>&1 || {
	    LOOP_DEV="$base$i"
	    break
	}
    done
    echo $LOOP_DEV
}

setup_loop() {
    local LOOP_DEV=$1
    local LOOP_FILE=$2
    
    dd if=/dev/zero of=$LOOP_FILE bs=1M count=10 2>/dev/null || return $?

    losetup $LOOP_DEV $LOOP_FILE || {
	rc=$?
	cleanup_loop $LOOP_DEV $LOOP_FILE
	return $rc
    }
    
    mke2fs -F $LOOP_DEV >/dev/null 2>&1 || {
	rc=$?
	cleanup_loop $LOOP_DEV $LOOP_FILE
	echo "cannot create test ext2 fs on $LOOP_DEV"
	return $?
    }
    return 0
}

cleanup_loop() {
    local LOOP_DEV=$1
    local LOOP_FILE=$2
    
    losetup -d $LOOP_DEV >/dev/null 2>&1
    rm -fr $LOOP_FILE >/dev/null 2>&1
}

setup_upcall() {
    local INJECTION=""
    local UPCALL=$1
    local MODE=$2
    local LOG=$3
    local BG=$4
    
    test "x$BG" = "xBACKGROUND" && 
	BG="&" || BG=""
    
    test "x$MODE" = "xDEADLOCK" &&
	INJECTION="touch \$MNTPATH/file"
    
    cat > $UPCALL <<- EOF
#!/bin/sh

MOUNT=\`which mount 2>/dev/null\`
test "x\$MOUNT" = "x" && MOUNT="/bin/mount"

OPTIONS=\$1
MNTPATH=\$2

test "x\$OPTIONS" = "x" || "x\$MNTPATH" = "x" &&
exit 1

$INJECTION
\$MOUNT \$OPTIONS \$MNTPATH > $LOG 2>&1 $BG
exit \$?
EOF
    chmod +x $UPCALL
    return $?
}

cleanup_upcall() {
    local UPCALL=$1
    rm -fr $UPCALL
}

show_log() {
    local LOG=$1
    
    test -f $LOG && {
	echo "======================== upcall log ==========================="
	cat $LOG
	echo "==============================================================="
    }
}

check_mnt()
{
    local OBJECT=$1
    local mnt=""
    local p=""
    
    mnt="`cat /proc/mounts | grep $OBJECT | awk '{print \$2}'`"
    test -z "$mnt" && return 1
    
    for p in $mnt; do
	test "x$p" = "x$OBJECT" || return 1
    done
    
    return 0
}

check_gns() {
    local LOG="/tmp/gns-log"
    local UPCALL_PATH=""
    
    local UPCALL=$1
    local OBJECT1=$2
    local OBJECT2=$3
    local TIMOUT=$4
    local TICK=$5
    local MODE=$6
    local BG=$7
    
    rm -fr $LOG >/dev/null 2>&1
    UPCALL_PATH="/tmp/gns-upcall-$UPCALL.sh"
    
    echo "generating upcall $UPCALL_PATH"
    setup_upcall $UPCALL_PATH $UPCALL $LOG $BG || return $rc

    echo "======================== upcall script ==========================="
    cat $UPCALL_PATH 2>/dev/null || return $?
    echo "=================================================================="
   
    echo "$UPCALL_PATH" > /proc/fs/lustre/llite/fs0/gns_upcall || return $?
    echo "upcall:  $(cat /proc/fs/lustre/llite/fs0/gns_upcall)"

#    local OLD_PWD=$(pwd)
    case "$MODE" in
	GENERIC)
	    echo -n "mount on open $OBJECT1/test_file1 (generic): "
	    echo -n "test data" > $OBJECT1/test_file1 >/dev/null 2>&1 || return $?
#	    cd $OBJECT1 || return $?
	    ;;
	CONCUR1)
	    local i=1
	    local nr=20
	
	    echo -n "mount on open $OBJECT1/test_file1 ($nr threads): "
	    for ((;i<=$nr;i++)); do 
		echo -n "test data" > $OBJECT1/test_file$i >/dev/null 2>&1 &
	    done
	
	    wait
	    
	    local RETVAL=$?
	    
	    [ $RETVAL -eq 0 ] || 
		return $RETVAL
	    ;;
	CONCUR2)
	    test "x$OBJECT2" = "x" && {
		echo "not defined object2 for concurrent2 testing"
		return 1
	    }
	    echo -n "mount on open $OBJECT1/test_file1: "
	    echo -n "mount on open $OBJECT2/test_file1: "
	    echo -n "test data" > $OBJECT1/test_file1 >/dev/null 2>&1 &
	    echo -n "test data" > $OBJECT2/test_file1 >/dev/null 2>&1 &
	    
	    wait
	    
	    local RETVAL=$?
	    
	    [ $RETVAL -eq 0 ] || 
		return $RETVAL
	    ;;
	CONCUR3)
	    echo -n "mount on open $OBJECT1/test_file1: "
	    
	    local i=1
	    local nr=20
	    
	    for ((;i<$nr;i++)); do
		touch $OBJECT1/file$i &
		echo -n "test data" > $OBJECT1/test_file$i >/dev/null 2>&1 &
		mkdir $OBJECT1/dir$i &
	    done

	    wait
	    
	    local RETVAL=$?
	    
	    [ $RETVAL -eq 0 ] || 
		return $RETVAL
	    ;;
	*)
	    echo "invalid testing mode $MODE"
	    return 1
    esac

#    cd $OLD_PWD
    
    check_mnt $OBJECT1 || {
	echo "fail"
	show_log $LOG
	return 1
    }
    
    if test "x$MODE" = "xCONCUR2"; then
	check_mnt $OBJECT2 || {
	    echo "fail"
	    show_log $LOG
	    return 1
	}
    fi
    
    echo "success"

    local sleep_time=$TIMOUT
    let sleep_time+=$TICK*2
    echo -n "waiting for umount ${sleep_time}s (timeout + tick*2): "
    sleep $sleep_time
    
    check_mnt $OBJECT1 && {
	echo "failed"
	return 2
    }
    
    if test "x$MODE" = "xCONCUR2"; then
	check_mnt $OBJECT2 && {
	    echo "failed"
	    return 2
	}
    fi
    
    echo "success"
    cleanup_upcall $UPCALL_PATH
    return 0
}

setup_object() {
    local OBJPATH=$1
    local OBJECT=$2
    local CONTENT=$3
    
    mkdir -p $OBJPATH || return $?
    echo -n $CONTENT > $OBJPATH/$OBJECT || return $?
    
    echo "======================== mount object ==========================="
    cat $OBJPATH/$OBJECT
    echo ""
    echo "================================================================="
    
    chmod u+s $OBJPATH
    return $?
}

cleanup_object() {
    local OBJPATH=$1

    chmod u-s $OBJPATH
    umount $OBJPATH >/dev/null 2>&1
    rm -fr $OBJPATH >/dev/null 2>&1
}

setup_gns() {
    local OBJECT=$1
    local TIMOUT=$2
    local TICK=$3

    echo "$OBJECT" > /proc/fs/lustre/llite/fs0/gns_object_name || error
    echo "$TIMOUT" > /proc/fs/lustre/llite/fs0/gns_timeout || error
    echo "$TICK" > /proc/fs/lustre/llite/fs0/gns_tick || error

    echo ""
    echo "timeout: $(cat /proc/fs/lustre/llite/fs0/gns_timeout)s"
    echo "object:  $(cat /proc/fs/lustre/llite/fs0/gns_object_name)"
    echo "tick:    $(cat /proc/fs/lustre/llite/fs0/gns_tick)s"
    echo ""

}

enable_gns()
{
    echo "1" > /proc/fs/lustre/llite/fs0/gns_enabled || error
    test "x$(cat /proc/fs/lustre/llite/fs0/gns_enabled)" = "x1" || error
}

disable_gns()
{
    echo "0" > /proc/fs/lustre/llite/fs0/gns_enabled || error
    test "x$(cat /proc/fs/lustre/llite/fs0/gns_enabled)" = "x0" || error
}

test_1a() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local LOOP_FILE="/tmp/gns_loop_1a"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    echo "preparing loop device $LOOP_DEV <-> $LOOP_FILE..."
    cleanup_loop $LOOP_DEV $LOOP_FILE
    setup_loop $LOOP_DEV $LOOP_FILE || error

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error
    
    disable_gns

    echo "preparing mount object at $DIR/gns_test_1a/$OBJECT..."
    setup_object $DIR/gns_test_1a $OBJECT "-t ext2 $LOOP_DEV" || error

    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall 3 times on the row"
    
    for ((i=0;i<3;i++)); do
	check_gns GENERIC $DIR/gns_test_1a $DIR/gns_test_1a $TIMOUT $TICK GENERIC || {
	    disable_gns
	    cleanup_object $DIR/gns_test_1a
	    cleanup_loop $LOOP_DEV $LOOP_FILE
	    error
	}
    done
    
    disable_gns

    cleanup_object $DIR/gns_test_1a
    cleanup_loop $LOOP_DEV $LOOP_FILE
}

run_test 1a " general GNS test - mount/umount (GENERIC) ================"

test_1b() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local LOOP_FILE="/tmp/gns_loop_1b"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    echo "preparing loop device $LOOP_DEV <-> $LOOP_FILE..."
    cleanup_loop $LOOP_DEV $LOOP_FILE
    setup_loop $LOOP_DEV $LOOP_FILE || error

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns
    
    echo "preparing mount object at $DIR/gns_test_1b/$OBJECT..."
    setup_object $DIR/gns_test_1b $OBJECT "-t ext2 $LOOP_DEV" || error
    
    enable_gns

    echo ""
    echo "testing GNS with DEADLOCK upcall 3 times on the row"
    
    for ((i=0;i<3;i++)); do
	check_gns DEADLOCK $DIR/gns_test_1b $DIR/gns_test_1b $TIMOUT $TICK GENERIC || {
	    disable_gns
	    cleanup_object $DIR/gns_test_1b
	    cleanup_loop $LOOP_DEV $LOOP_FILE
	    error
	}
    done
    
    disable_gns

    cleanup_object $DIR/gns_test_1b
    cleanup_loop $LOOP_DEV $LOOP_FILE
}

run_test 1b " general GNS test - mount/umount (DEADLOCK) ==============="

test_1c() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local LOOP_FILE="/tmp/gns_loop_1c"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    echo "preparing loop device $LOOP_DEV <-> $LOOP_FILE..."
    cleanup_loop $LOOP_DEV $LOOP_FILE
    setup_loop $LOOP_DEV $LOOP_FILE || error

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns

    echo "preparing mount object at $DIR/gns_test_1c/$OBJECT..."
    setup_object $DIR/gns_test_1c $OBJECT "-t ext2 $LOOP_DEV" || error

    enable_gns

    echo ""
    echo "testing GNS with GENERIC/DEADLOCK upcall 4 times on the row in GENERIC mode"
    local i=0
    
    for ((;i<4;i++)); do
	local MODE="GENERIC"
	
	test $(($i%2)) -eq 1 && MODE="DEADLOCK"
	
	check_gns $MODE $DIR/gns_test_1c $DIR/gns_test_1c $TIMOUT $TICK GENERIC || {
	    disable_gns
	    cleanup_object $DIR/gns_test_1c
	    cleanup_loop $LOOP_DEV $LOOP_FILE
	    error
	}
    done
    
    disable_gns

    cleanup_object $DIR/gns_test_1c
    cleanup_loop $LOOP_DEV $LOOP_FILE
}

run_test 1c " general GNS test - mount/umount (GENERIC/DEADLOCK) ========"

test_1d() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local LOOP_FILE="/tmp/gns_loop_1d"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    echo "preparing loop device $LOOP_DEV <-> $LOOP_FILE..."
    cleanup_loop $LOOP_DEV $LOOP_FILE
    setup_loop $LOOP_DEV $LOOP_FILE || error

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns

    echo "preparing mount object at $DIR/gns_test_1d/$OBJECT..."
    setup_object $DIR/gns_test_1d $OBJECT "-t ext2 $LOOP_DEV" || error

    enable_gns

    echo ""
    echo "testing GNS with GENERIC/DEADLOCK upcall 4 times on the row in CONCUR1 mode"
    local i=0
    
    for ((;i<4;i++)); do
	local MODE="GENERIC"
	
	test $(($i%2)) -eq 1 && MODE="DEADLOCK"
	
	check_gns $MODE $DIR/gns_test_1d $DIR/gns_test_1d $TIMOUT $TICK CONCUR1 || {
	    disable_gns
	    cleanup_object $DIR/gns_test_1d
	    cleanup_loop $LOOP_DEV $LOOP_FILE
	    error
	}
    done
    
    disable_gns

    cleanup_object $DIR/gns_test_1d
    cleanup_loop $LOOP_DEV $LOOP_FILE
}

run_test 1d " general GNS test - concurrent mount ======================="

test_1e() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local LOOP_FILE="/tmp/gns_loop_1e"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    echo "preparing loop device $LOOP_DEV <-> $LOOP_FILE..."
    cleanup_loop $LOOP_DEV $LOOP_FILE
    setup_loop $LOOP_DEV $LOOP_FILE || error

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns

    echo "preparing mount object at $DIR/gns_test_1e1/$OBJECT..."
    setup_object $DIR/gns_test_1e1 $OBJECT "-t ext2 $LOOP_DEV" || error
    
    echo "preparing mount object at $DIR/gns_test_1e2/$OBJECT..."
    setup_object $DIR/gns_test_1e2 $OBJECT "-t ext2 $LOOP_DEV" || error

    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall in CONCUR2 mode"
    
    check_gns GENERIC $DIR/gns_test_1e1 $DIR/gns_test_1e2 $TIMOUT $TICK CONCUR2 || {
	disable_gns
        cleanup_object $DIR/gns_test_1e1
        cleanup_object $DIR/gns_test_1e2
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error
    }
    
    disable_gns

    cleanup_object $DIR/gns_test_1e1
    cleanup_object $DIR/gns_test_1e2
    cleanup_loop $LOOP_DEV $LOOP_FILE
}

run_test 1e " general GNS test - concurrent mount of 2 GNS mounts ======="

test_2a() {
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns

    echo "preparing mount object at $DIR/gns_test_2a/$OBJECT..."
    mkdir -p $DIR/gns_test_2a
    ln -s $DIR/gns_test_2a $DIR/gns_test_2a/$OBJECT
    chmod u+s $DIR/gns_test_2a
    
    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall"
    
    check_gns GENERIC $DIR/gns_test_2a $DIR/gns_test_2a $TIMOUT $TICK GENERIC && {
	disable_gns
	chmod u-s $DIR/gns_test_2a
	rm -fr $DIR/gns_test_2a
        error "symlink as mount object works?"
    }
    
    disable_gns
    chmod u-s $DIR/gns_test_2a
    rm -fr $DIR/gns_test_2a
}

run_test 2a " odd conditions (mount object is symlink) ============="

test_2b() {
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns

    echo "preparing mount object at $DIR/gns_test_2b/$OBJECT..."
    mkdir -p $DIR/gns_test_2b/$OBJECT
    chmod u+s $DIR/gns_test_2b
    
    enable_gns
    
    echo ""
    echo "testing GNS with GENERIC upcall"
    
    check_gns GENERIC $DIR/gns_test_2b $DIR/gns_test_2b $TIMOUT $TICK GENERIC && {
	disable_gns
	chmod u-s $DIR/gns_test_2b
	rm -fr $DIR/gns_test_2b
        error "dir as mount object works?"
    }
    
    disable_gns
    chmod u-s $DIR/gns_test_2b
    rm -fr $DIR/gns_test_2b
}

run_test 2b " odd conditions (mount object is directory) ==========="

test_2c() {
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns

    echo "preparing mount object at $DIR/gns_test_2c/$OBJECT..."
    mkdir -p $DIR/gns_test_2c/$OBJECT/$OBJECT/$OBJECT/$OBJECT
    chmod u+s -R $DIR/gns_test_2c
    
    enable_gns
    
    echo ""
    echo "testing GNS with GENERIC upcall"
    
    check_gns GENERIC $DIR/gns_test_2c $DIR/gns_test_2c $TIMOUT $TICK GENERIC && {
	disable_gns
	chmod u-s -R $DIR/gns_test_2c
	rm -fr $DIR/gns_test_2c
        error "recursive mounting of dir as mount object works?"
    }
    
    disable_gns
    chmod u-s $DIR/gns_test_2c
    rm -fr $DIR/gns_test_2c
}

run_test 2c " odd conditions (mount object is recursive dir) ======="

test_2d() {
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns

    echo "preparing mount object at $DIR/gns_test_2d/$OBJECT..."
    mkdir -p $DIR/gns_test_2d
    chmod u+s $DIR/gns_test_2d
    
    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall"
    
    check_gns GENERIC $DIR/gns_test_2d $DIR/gns_test_2d $TIMOUT $TICK GENERIC && {
	disable_gns
	chmod u-s $DIR/gns_test_2d
	rm -fr $DIR/gns_test_2d
        error "mount point with absent mount object works?"
    }
    
    disable_gns
    chmod u-s $DIR/gns_test_2d
    rm -fr $DIR/gns_test_2d
}

run_test 2d " odd conditions (mount object is absent) =============="

test_2e() {
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    echo "." > /proc/fs/lustre/llite/fs0/gns_object_name
    test "x$(cat /proc/fs/lustre/llite/fs0/gns_object_name)" = "x." && 
	error "'.' is set as mount object name"

    echo ".." > /proc/fs/lustre/llite/fs0/gns_object_name
    test "x$(cat /proc/fs/lustre/llite/fs0/gns_object_name)" = "x.." && 
	error "'..' is set as mount object name"

    echo ".a" > /proc/fs/lustre/llite/fs0/gns_object_name
    test "x$(cat /proc/fs/lustre/llite/fs0/gns_object_name)" = "x.a" || 
	error "'.a' is not set as mount object name"

    echo "..a" > /proc/fs/lustre/llite/fs0/gns_object_name
    test "x$(cat /proc/fs/lustre/llite/fs0/gns_object_name)" = "x..a" || 
	error "'..a' is not set as mount object name"
}

run_test 2e " odd conditions ('.' and '..' as mount object) ============="

test_2f() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local LOOP_FILE="/tmp/gns_loop_2f"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    echo "preparing loop device $LOOP_DEV <-> $LOOP_FILE..."
    cleanup_loop $LOOP_DEV $LOOP_FILE
    setup_loop $LOOP_DEV $LOOP_FILE || error

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns

    echo "preparing mount object at $DIR/gns_test_2f/$OBJECT..."
    setup_object $DIR/gns_test_2f $OBJECT "-t ext2 $LOOP_DEV" || error

    enable_gns

    echo ""
    echo "testing GNS with DEADLOCK upcall in CONCUR3 mode"
    
    local MODE="DEADLOCK"
	
    check_gns $MODE $DIR/gns_test_2f $DIR/gns_test_2f $TIMOUT $TICK CONCUR3 || {
        disable_gns
        cleanup_object $DIR/gns_test_2f
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error
    }
    
    disable_gns

    cleanup_object $DIR/gns_test_2f
    cleanup_loop $LOOP_DEV $LOOP_FILE
}

run_test 2f " odd conditions (mount point is modifying during mount) ===="

test_2g() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local LOOP_FILE="/tmp/gns_loop_2g"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    echo "preparing loop device $LOOP_DEV <-> $LOOP_FILE..."
    cleanup_loop $LOOP_DEV $LOOP_FILE
    setup_loop $LOOP_DEV $LOOP_FILE || error

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns

    echo "preparing mount object at $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT..."
    setup_object $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT \
$OBJECT "-t ext2 $LOOP_DEV" || error
    chmod u+s $DIR/gns_test_2g -R

    enable_gns

    echo ""
    echo "testing GNS with DEADLOCK upcall in GENERIC mode"
    
    local MODE="DEADLOCK"
	
    check_gns $MODE $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT \
$DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT $TIMOUT $TICK GENERIC || {
        disable_gns
        cleanup_object $DIR/gns_test_2g
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error "recursive mount point does not work"
    }
    
    disable_gns

    echo ""
    echo "turning SUID on $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT off"
    chmod u-s $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT

    enable_gns

    check_gns $MODE $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT \
$DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT $TIMOUT $TICK GENERIC && {
        disable_gns
        cleanup_object $DIR/gns_test_2g
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error "GNS works whereas mount point is not SUID marked dir"
    }

    disable_gns

    cleanup_object $DIR/gns_test_2g
    cleanup_loop $LOOP_DEV $LOOP_FILE
}

run_test 2g " odd conditions (mount point is recursive marked SUID dir) ="

test_2h() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local LOOP_FILE="/tmp/gns_loop_2h"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    echo "preparing loop device $LOOP_DEV <-> $LOOP_FILE..."
    cleanup_loop $LOOP_DEV $LOOP_FILE
    setup_loop $LOOP_DEV $LOOP_FILE || error

    echo "setting up GNS timeouts and mount object..."
    setup_gns $OBJECT $TIMOUT $TICK || error

    disable_gns

    echo "preparing mount object at $DIR/gns_test_2h/$OBJECT..."
    setup_object $DIR/gns_test_2h $OBJECT "-t ext2 $LOOP_DEV" || error

    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall in GENERIC mode"
    
    check_gns GENERIC $DIR/gns_test_2h $DIR/gns_test_2h \
$TIMOUT $TICK GENERIC BACKGROUND || {
        disable_gns
        cleanup_object $DIR/gns_test_2h
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error
    }
    
    disable_gns

    cleanup_object $DIR/gns_test_2h
    cleanup_loop $LOOP_DEV $LOOP_FILE
}

run_test 2h " odd conditions (mounting in background) ==================="

TMPDIR=$OLDTMPDIR
TMP=$OLDTMP
HOME=$OLDHOME

log "cleanup: ==========================================================="
if [ "`mount | grep ^$NAME`" ]; then
	rm -rf $DIR/[Rdfs][1-9]*
	if [ "$I_MOUNTED" = "yes" ]; then
		sh llmountcleanup.sh || error
	fi
fi

echo '=========================== finished ==============================='
[ -f "$SANITYLOG" ] && cat $SANITYLOG && exit 1 || true
