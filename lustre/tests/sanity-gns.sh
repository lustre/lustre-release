#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-"1b 1c"}
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
EXT2_DEV=${EXT2_DEV:-$TMP/SANITY.LOOP}
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
    
    echo "preparing loop device $LOOP_DEV <-> $LOOP_FILE..."
    cleanup_loop $LOOP_DEV $LOOP_FILE
    
    dd if=/dev/zero of=$LOOP_FILE bs=1M count=10 2>/dev/null || 
	return $?

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
    
    echo "generating upcall $UPCALL"

    test "x$BG" = "xBG" && 
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

    echo "$UPCALL" > /proc/fs/lustre/llite/fs0/gns_upcall || return $?
    echo "upcall:  $(cat /proc/fs/lustre/llite/fs0/gns_upcall)"

    echo "======================== upcall script ==========================="
    cat $UPCALL 2>/dev/null || return $?
    echo "=================================================================="
   
    return 0
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

sleep_on()
{
    local TIMOUT=$1
    local TICK=$2
    
    local sleep_time=$TIMOUT
    let sleep_time+=$TICK*2
    sleep $sleep_time
}

check_mnt()
{
    local OBJECT=$1
    local MODE=$2
    local TIMOUT=$3
    local TICK=$4
    
    local res=0
    local mnt=""
    local p=""
    local op
    
    test $MODE -eq 1 && op="mount" || op="umount"
    echo -n "checking for $op $OBJECT: "

    test $MODE -eq 0 && sleep_on $TIMOUT $TICK

    OBJECT="`echo $OBJECT | sed 's/\/*$//'`"
    mnt="`cat /proc/mounts | grep $OBJECT | awk '{print \$2}'`"
    test -z "$mnt" && {
	res=0
    } || {
	for p in $mnt; do
	    test "x$p" = "x$OBJECT" && {
		res=1
		break
	    }
	done
    }
    
    if test $MODE -eq 0; then
	test $res -eq 1 && {
	    echo "failed"
	    return 1
	}
    else
	test $res -eq 0 && {
	    echo "failed"
	    return 1
	}
    fi

    echo "success"    
    return 0
}

check_gns() {
    local OBJECT1=$1
    local OBJECT2=$2
    local TIMOUT=$3
    local TICK=$4
    local MODE=$5
    local OP=$6
    local CHECK=$7
    
    local OLD_PWD=$(pwd)
    echo "testing mount on $OP against $OBJECT1 in $MODE mode"
    
    case "$MODE" in
	GENERIC)
	    case "$OP" in
		OPEN)
		    echo -n "test data" > $OBJECT1/test_file1 >/dev/null 2>&1
		    ;;
		LIST)
		    ls -la $OBJECT1/
		    ;;
		CHDIR)
		    cd $OBJECT1 || return $?
		    ;;
		*)
		    echo "invalid testing operation $OP"
		    return 1
	    esac
	    ;;
	CONCUR1)
	    local i=1
	    local nr=20
	
	    for ((;i<=$nr;i++)); do 
		case "$OP" in
		    OPEN)
			echo -n "test data" > $OBJECT1/test_file$i >/dev/null 2>&1 &
			;;
		    LIST)
			ls -la $OBJECT1/
			;;
		    CHDIR)
			cd $OBJECT1 >/dev/null 2>&1 &
			;;
		    *)
			echo "invalid testing operation $OP"
			return 1
		esac
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
	    case "$OP" in
	        OPEN)
		    echo -n "test data" > $OBJECT1/test_file1 >/dev/null 2>&1 &
		    echo -n "test data" > $OBJECT2/test_file1 >/dev/null 2>&1 &
		    ;;
		LIST)
		    ls -la $OBJECT1/
		    ls -la $OBJECT2/
		    ;;
		CHDIR)
		    cd $OBJECT1 >/dev/null 2>&1 &
		    cd $OBJECT2 >/dev/null 2>&1 &
		    ;;
		*)
		    echo "invalid testing operation $OP"
		    return 1
	    esac
	    
	    wait
	    
	    local RETVAL=$?
	    
	    [ $RETVAL -eq 0 ] || 
		return $RETVAL
	    ;;
	CONCUR3)
	    local i=1
	    local nr=20
	    
	    for ((;i<$nr;i++)); do
		case "$OP" in
	    	    OPEN)
			touch $OBJECT1/file$i &
			echo -n "test data" > $OBJECT1/test_file$i >/dev/null 2>&1 &
			mkdir $OBJECT1/dir$i &
			;;
		    LIST)
			touch $OBJECT1/file &
			ls -la $OBJECT1/ &
			mkdir $OBJECT1/dir$i &
			;;
		    CHDIR)
			touch $OBJECT1/file$i &
			cd $OBJECT1 >/dev/null 2>&1 &
			mkdir $OBJECT1/dir$i &
			;;
		    *)
			echo "invalid testing operation $OP"
			return 1
		esac
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

    test "x$OP" = "xCHDIR" && cd $OLD_PWD

    test $CHECK -eq 1 && {
	# check if mount is here
	check_mnt $OBJECT1 1 0 0 || return 1
	if test "x$MODE" = "xCONCUR2"; then
	    check_mnt $OBJECT2 1 0 0 || return 1
	fi
    
	# wait for $TIMEOUT and check for mount, it should go
	check_mnt $OBJECT1 0 $TIMOUT $TICK || return 2
	if test "x$MODE" = "xCONCUR2"; then
	    check_mnt $OBJECT2 0 $TIMOUT $TICK || return 2
	fi
    }
    
    return 0
}

setup_object() {
    local OBJPATH=$1
    local OBJECT=$2
    local CONTENT=$3
    
    echo "preparing mount object at $OBJPATH..."
    
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

    echo "setting up GNS timeouts and mount object..."

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
    echo "1" > /proc/fs/lustre/llite/fs0/gns_enabled
    test "x$(cat /proc/fs/lustre/llite/fs0/gns_enabled)" = "x1" || 
	error "cannot enable GNS"
}

disable_gns()
{
    echo "0" > /proc/fs/lustre/llite/fs0/gns_enabled
    test "x$(cat /proc/fs/lustre/llite/fs0/gns_enabled)" = "x0" || 
	error "cannot disable GNS"
}

test_1a() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local UPCALL="$TMP/gns-upcall-1a.sh"
    local LOOP_FILE="$TMP/gns_loop_1a"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    setup_loop $LOOP_DEV $LOOP_FILE || 
	error

    setup_upcall $UPCALL GENERIC $LOG FG || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_gns $OBJECT $TIMOUT $TICK || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }
    
    setup_object $DIR/gns_test_1a $OBJECT "-t ext2 $LOOP_DEV" || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall 3 times on the row"
    
    for ((i=0;i<3;i++)); do
	check_gns $DIR/gns_test_1a $DIR/gns_test_1a $TIMOUT $TICK GENERIC OPEN 1 || {
	    disable_gns
	    show_log $LOG
	    cleanup_object $DIR/gns_test_1a
	    cleanup_loop $LOOP_DEV $LOOP_FILE
	    error
	}
    done
    
    for ((i=0;i<3;i++)); do
	check_gns $DIR/gns_test_1a $DIR/gns_test_1a $TIMOUT $TICK GENERIC CHDIR 1 || {
	    disable_gns
	    show_log $LOG
	    cleanup_object $DIR/gns_test_1a
	    cleanup_loop $LOOP_DEV $LOOP_FILE
	    error
	}
    done
    
    disable_gns
    cleanup_object $DIR/gns_test_1a
    cleanup_loop $LOOP_DEV $LOOP_FILE

    return 0
}

run_test 1a " general GNS test - mount/umount (GENERIC) ================"

test_1b() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local UPCALL="$TMP/gns-upcall-1b.sh"
    local LOOP_FILE="$TMP/gns_loop_1b"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    setup_loop $LOOP_DEV $LOOP_FILE || 
	error

    setup_upcall $UPCALL DEADLOCK $LOG FG || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_gns $OBJECT $TIMOUT $TICK || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_object $DIR/gns_test_1b $OBJECT "-t ext2 $LOOP_DEV" || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }
    
    enable_gns

    echo ""
    echo "testing GNS with DEADLOCK upcall 3 times on the row"
    
    for ((i=0;i<3;i++)); do
	check_gns $DIR/gns_test_1b $DIR/gns_test_1b $TIMOUT $TICK GENERIC OPEN 1
    done
    
    disable_gns
    cleanup_object $DIR/gns_test_1b
    cleanup_loop $LOOP_DEV $LOOP_FILE

    return 0
}

run_test 1b " general GNS test - mount/umount (DEADLOCK) ==============="

test_1c() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local UPCALL="$TMP/gns-upcall-1c.sh"
    local LOOP_FILE="$TMP/gns_loop_1c"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    setup_loop $LOOP_DEV $LOOP_FILE || 
	error

    setup_gns $OBJECT $TIMOUT $TICK || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_object $DIR/gns_test_1c $OBJECT "-t ext2 $LOOP_DEV" || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    enable_gns

    echo ""
    echo "testing GNS with GENERIC/DEADLOCK upcall 4 times on the row in GENERIC mode"
    local i=0
    
    for ((;i<4;i++)); do
	local UPCALL_MODE
	
	test $(($i%2)) -eq 1 && UPCALL_MODE="DEADLOCK" || 
	    UPCALL_MODE="GENERIC"
	    
	setup_upcall $UPCALL $UPCALL_MODE $LOG FG || {
	    disable_gns
	    show_log $LOG
	    cleanup_object $DIR/gns_test_1c
	    cleanup_loop $LOOP_DEV $LOOP_FILE
	    error
	}

	check_gns $DIR/gns_test_1c $DIR/gns_test_1c $TIMOUT $TICK GENERIC OPEN 1 || {
	    disable_gns
	    show_log $LOG
	    cleanup_object $DIR/gns_test_1c
	    cleanup_loop $LOOP_DEV $LOOP_FILE
	    error
	}
    done
    
    disable_gns
    cleanup_object $DIR/gns_test_1c
    cleanup_loop $LOOP_DEV $LOOP_FILE

    return 0
}

run_test 1c " general GNS test - mount/umount (GENERIC/DEADLOCK) ========"

test_1d() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local UPCALL="$TMP/gns-upcall-1d.sh"
    local LOOP_FILE="$TMP/gns_loop_1d"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    setup_loop $LOOP_DEV $LOOP_FILE || 
	error

    setup_upcall $UPCALL GENERIC $LOG FG || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_gns $OBJECT $TIMOUT $TICK || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_object $DIR/gns_test_1d $OBJECT "-t ext2 $LOOP_DEV" || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }
    
    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall 4 times on the row in CONCUR1 mode"
    local i=0
    
    for ((;i<4;i++)); do
	check_gns $DIR/gns_test_1d $DIR/gns_test_1d $TIMOUT $TICK CONCUR1 OPEN 1 || {
	    disable_gns
	    show_log $LOG
	    cleanup_object $DIR/gns_test_1d
	    cleanup_loop $LOOP_DEV $LOOP_FILE
	    error
	}
    done
    
    disable_gns
    cleanup_object $DIR/gns_test_1d
    cleanup_loop $LOOP_DEV $LOOP_FILE

    return 0
}

run_test 1d " general GNS test - concurrent mount ======================="

test_1e() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local UPCALL="$TMP/gns-upcall-1e.sh"
    local LOOP_FILE="$TMP/gns_loop_1e"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    setup_loop $LOOP_DEV $LOOP_FILE || 
	error

    setup_upcall $UPCALL GENERIC $LOG FG || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_gns $OBJECT $TIMOUT $TICK || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_object $DIR/gns_test_1e1 $OBJECT "-t ext2 $LOOP_DEV" || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }
    
    setup_object $DIR/gns_test_1e2 $OBJECT "-t ext2 $LOOP_DEV" || {
        cleanup_object $DIR/gns_test_1e1
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }
    
    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall in CONCUR2 mode"
    
    check_gns $DIR/gns_test_1e1 $DIR/gns_test_1e2 $TIMOUT $TICK CONCUR2 OPEN 1 || {
	disable_gns
	show_log $LOG
        cleanup_object $DIR/gns_test_1e1
        cleanup_object $DIR/gns_test_1e2
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error
    }
    
    disable_gns
    cleanup_object $DIR/gns_test_1e1
    cleanup_object $DIR/gns_test_1e2
    cleanup_loop $LOOP_DEV $LOOP_FILE

    return 0
}

run_test 1e " general GNS test - concurrent mount of 2 GNS mounts ======="

test_2a() {
    local UPCALL="$TMP/gns-upcall-2a.sh"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    setup_gns $OBJECT $TIMOUT $TICK || 
	error

    setup_upcall $UPCALL GENERIC $LOG FG ||
	error

    echo "preparing mount object at $DIR/gns_test_2a/$OBJECT..."
    mkdir -p $DIR/gns_test_2a
    ln -s $DIR/gns_test_2a $DIR/gns_test_2a/$OBJECT
    chmod u+s $DIR/gns_test_2a
    
    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall"
    
    check_gns $DIR/gns_test_2a $DIR/gns_test_2a $TIMOUT $TICK GENERIC OPEN 1
    
    disable_gns
    chmod u-s $DIR/gns_test_2a
    rm -fr $DIR/gns_test_2a

    return 0
}

run_test 2a " odd conditions (mount object is symlink) ============="

test_2b() {
    local UPCALL="$TMP/gns-upcall-2b.sh"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    setup_gns $OBJECT $TIMOUT $TICK || 
	error

    setup_upcall $UPCALL GENERIC $LOG FG ||
	error

    echo "preparing mount object at $DIR/gns_test_2b/$OBJECT..."
    mkdir -p $DIR/gns_test_2b/$OBJECT
    chmod u+s $DIR/gns_test_2b
    
    enable_gns
    
    echo ""
    echo "testing GNS with GENERIC upcall"
    
    check_gns $DIR/gns_test_2b $DIR/gns_test_2b $TIMOUT $TICK GENERIC OPEN 1
    
    disable_gns
    chmod u-s $DIR/gns_test_2b
    rm -fr $DIR/gns_test_2b

    return 0
}

run_test 2b " odd conditions (mount object is directory) ==========="

test_2c() {
    local UPCALL="$TMP/gns-upcall-2c.sh"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    setup_gns $OBJECT $TIMOUT $TICK || 
	error

    setup_upcall $UPCALL GENERIC $LOG FG ||
	error

    echo "preparing mount object at $DIR/gns_test_2c/$OBJECT..."
    mkdir -p $DIR/gns_test_2c/$OBJECT/$OBJECT/$OBJECT/$OBJECT
    chmod u+s -R $DIR/gns_test_2c
    
    enable_gns
    
    echo ""
    echo "testing GNS with GENERIC upcall"
    
    check_gns $DIR/gns_test_2c $DIR/gns_test_2c $TIMOUT $TICK GENERIC OPEN 1

    disable_gns
    chmod u-s -R $DIR/gns_test_2c
    rm -fr $DIR/gns_test_2c

    return 0
}

run_test 2c " odd conditions (mount object is recursive dir) ======="

test_2d() {
    local UPCALL="$TMP/gns-upcall-2d.sh"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    setup_gns $OBJECT $TIMOUT $TICK || 
	error

    setup_upcall $UPCALL GENERIC $LOG FG ||
	error

    echo "preparing mount object at $DIR/gns_test_2d/$OBJECT..."
    mkdir -p $DIR/gns_test_2d
    chmod u+s $DIR/gns_test_2d
    
    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall"
    
    check_gns $DIR/gns_test_2d $DIR/gns_test_2d $TIMOUT $TICK GENERIC OPEN 1
    
    disable_gns
    chmod u-s $DIR/gns_test_2d
    rm -fr $DIR/gns_test_2d

    return 0
}

run_test 2d " odd conditions (mount object is absent) =============="

test_2e() {
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

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

    return 0
}

run_test 2e " odd conditions ('.' and '..' as mount object) ============="

test_2f() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local UPCALL="$TMP/gns-upcall-2f.sh"
    local LOOP_FILE="$TMP/gns_loop_2f"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    setup_loop $LOOP_DEV $LOOP_FILE || 
	error

    setup_upcall $UPCALL GENERIC $LOG FG || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_gns $OBJECT $TIMOUT $TICK || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_object $DIR/gns_test_2f $OBJECT "-t ext2 $LOOP_DEV" || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }
    
    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall in CONCUR3 mode"
    
    check_gns $DIR/gns_test_2f $DIR/gns_test_2f $TIMOUT $TICK CONCUR3 OPEN 1 || {
        disable_gns
	show_log $LOG
        cleanup_object $DIR/gns_test_2f
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error
    }
    
    disable_gns
    cleanup_object $DIR/gns_test_2f
    cleanup_loop $LOOP_DEV $LOOP_FILE

    return 0
}

run_test 2f " odd conditions (mount point is modifying during mount) ===="

test_2g() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local UPCALL="$TMP/gns-upcall-2g.sh"
    local LOOP_FILE="$TMP/gns_loop_2g"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    setup_loop $LOOP_DEV $LOOP_FILE || 
	error

    setup_upcall $UPCALL GENERIC $LOG FG || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_gns $OBJECT $TIMOUT $TICK || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_object $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT $OBJECT "-t ext2 $LOOP_DEV" || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }
    chmod u+s $DIR/gns_test_2g -R

    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall in GENERIC mode"
    
    check_gns $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT \
$DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT $TIMOUT $TICK GENERIC OPEN 1 || {
        disable_gns
	show_log $LOG
        cleanup_object $DIR/gns_test_2g
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error "recursive mount point does not work"
    }
    
    disable_gns

    echo ""
    echo "turning SUID on $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT off"
    chmod u-s $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT

    enable_gns

    check_gns $DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT \
$DIR/gns_test_2g/$OBJECT/$OBJECT/$OBJECT $TIMOUT $TICK GENERIC OPEN 1 && {
        disable_gns
	show_log $LOG
        cleanup_object $DIR/gns_test_2g
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error "GNS works whereas mount point is not SUID marked dir"
    }

    disable_gns
    cleanup_object $DIR/gns_test_2g
    cleanup_loop $LOOP_DEV $LOOP_FILE

    return 0
}

run_test 2g " odd conditions (mount point is recursive marked SUID dir) ="

test_2h() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local UPCALL="$TMP/gns-upcall-2h.sh"
    local LOOP_FILE="$TMP/gns_loop_2h"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    setup_loop $LOOP_DEV $LOOP_FILE || 
	error

    setup_upcall $UPCALL GENERIC $LOG BG || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_gns $OBJECT $TIMOUT $TICK || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_object $DIR/gns_test_2h $OBJECT "-t ext2 $LOOP_DEV" || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }
    
    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall in GENERIC mode"
    
    check_gns $DIR/gns_test_2h $DIR/gns_test_2h $TIMOUT $TICK GENERIC OPEN 1 || {
        disable_gns
	show_log $LOG
        cleanup_object $DIR/gns_test_2h
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error
    }
    
    disable_gns
    cleanup_object $DIR/gns_test_2h
    cleanup_loop $LOOP_DEV $LOOP_FILE

    return 0
}

run_test 2h " odd conditions (mounting in background) ==================="

test_3a() {
    local LOOP_DEV=$(find_free_loop 2>/dev/null)
    local UPCALL="$TMP/gns-upcall-3a.sh"
    local LOOP_FILE="$TMP/gns_loop_3a"
    local LOG="$TMP/gns-log"
    local OBJECT=".mntinfo"
    local TIMOUT=5
    local TICK=1

    disable_gns

    test "x$LOOP_DEV" != "x" && test -b $LOOP_DEV ||
	error "can't find free loop device"

    setup_loop $LOOP_DEV $LOOP_FILE || 
	error

    setup_upcall $UPCALL GENERIC $LOG FG || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_gns $OBJECT $TIMOUT $TICK || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }

    setup_object $DIR/gns_test_3a $OBJECT "-t ext2 $LOOP_DEV" || {
	cleanup_loop $LOOP_DEV $LOOP_FILE
	error
    }
    
    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall in GENERIC mode"
    
    check_gns $DIR/gns_test_3a $DIR/gns_test_3a $TIMOUT $TICK GENERIC OPEN 1 || {
        disable_gns
	show_log $LOG
        cleanup_object $DIR/gns_test_3a
        cleanup_loop $LOOP_DEV $LOOP_FILE
        error
    }
    
    chmod u-s $DIR/gns_test_3a || {
        disable_gns
        cleanup_object $DIR/gns_test_3a
        cleanup_loop $LOOP_DEV $LOOP_FILE
	error "can't chmod u-s $DIR/gns_test_3a"
    }
    
    check_mnt $DIR/gns_test_3a 0 0 0 || {
        disable_gns
        cleanup_object $DIR/gns_test_3a
        cleanup_loop $LOOP_DEV $LOOP_FILE
	error "chmod u-s $DIR/gns_test_3a caused mounting?"
    }
    
    disable_gns
    cleanup_object $DIR/gns_test_3a
    cleanup_loop $LOOP_DEV $LOOP_FILE
    
    return 0
}

run_test 3a " removing mnt by chmod u-s ================================="

test_3b() {
    local LOOP_FILE1="$TMP/gns_loop_3b1"
    local LOOP_FILE2="$TMP/gns_loop_3b2"
    local OBJECT=".mntinfo"
    local LOOP_DEV1=""
    local LOOP_DEV2=""
    local TIMOUT=5
    local TICK=1

    disable_gns

    LOOP_DEV1=$(find_free_loop 2>/dev/null)
    test "x$LOOP_DEV1" != "x" && test -b $LOOP_DEV1 ||
	error "can't find free loop device"

    setup_loop $LOOP_DEV1 $LOOP_FILE1 || error

    setup_object $DIR/gns_test_3b1 $OBJECT "-t ext2 $LOOP_DEV1" || {
        cleanup_loop $LOOP_DEV1 $LOOP_FILE1
	error
    }
    
    mkdir -p $TMP/mnt || error
    mount -t ext2 $LOOP_DEV1 $TMP/mnt || {
        cleanup_object $DIR/gns_test_3b1
        cleanup_loop $LOOP_DEV1 $LOOP_FILE1
	error "cannot mount $LOOP_DEV1"
    }

    mkdir $TMP/mnt/gns_test_3b2 || {
	umount $TMP/mnt
        cleanup_object $DIR/gns_test_3b1
        cleanup_loop $LOOP_DEV1 $LOOP_FILE1
	error "can't create $TMP/mnt/gns_test_3b2"
    }
    
    umount $TMP/mnt || {
        cleanup_object $DIR/gns_test_3b1
        cleanup_loop $LOOP_DEV1 $LOOP_FILE1
	error "can't umount $TMP/mnt"
    }

    setup_gns $OBJECT $TIMOUT $TICK || {
        cleanup_object $DIR/gns_test_3b1
        cleanup_loop $LOOP_DEV1 $LOOP_FILE1
	error
    }

    enable_gns

    echo ""
    echo "testing GNS with GENERIC upcall in GENERIC mode"
    
    check_gns $DIR/gns_test_3b1/gns_test_3b2 $DIR/gns_test_3b1/gns_test_3b2 \
$TIMOUT $TICK GENERIC LIST 0 || {
	disable_gns
	show_log $LOG
        cleanup_object $DIR/gns_test_3b1
        cleanup_loop $LOOP_DEV1 $LOOP_FILE1
        error
    }
    
    check_mnt $DIR/gns_test_3b1 1 0 0 || {
	disable_gns
	show_log $LOG
        cleanup_object $DIR/gns_test_3b1
        cleanup_loop $LOOP_DEV1 $LOOP_FILE1
        error
    }
    
    check_mnt $DIR/gns_test_3b1 0 $TIMOUT $TICK || {
	disable_gns
	show_log $LOG
        cleanup_object $DIR/gns_test_3b1
        cleanup_loop $LOOP_DEV1 $LOOP_FILE1
        error
    }

    disable_gns
    cleanup_object $DIR/gns_test_3b1
    cleanup_loop $LOOP_DEV1 $LOOP_FILE1

    return 0
}

run_test 3b " readdir through mount point ==============================="

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
