#!/bin/bash
# vim:expandtab:shiftwidth=4:softtabstop=4:tabstop=4:
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test:
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-""}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$SLOW" = "no" ] && EXCEPT="$EXCEPT"

# Tests that fail on uml, maybe elsewhere, FIXME
CPU=`awk '/model/ {print $4}' /proc/cpuinfo`
[ "$CPU" = "UML" ] && EXCEPT="$EXCEPT"

case `uname -r` in
2.6*) FSTYPE=${FSTYPE:-ldiskfs}; ALWAYS_EXCEPT="$ALWAYS_EXCEPT " ;;
*) error "unsupported kernel (gss only works with 2.6.x)" ;;
esac

SRCDIR=`dirname $0`
export PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$SRCDIR/../utils/gss:$PATH:/sbin

TMP=${TMP:-/tmp}

CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
CREATETEST=${CREATETEST:-createtest}
LFS=${LFS:-lfs}
LCTL=${LCTL:-lctl}
MEMHOG=${MEMHOG:-memhog}
DIRECTIO=${DIRECTIO:-directio}
ACCEPTOR_PORT=${ACCEPTOR_PORT:-988}
UMOUNT=${UMOUNT:-"umount -d"}

if [ $UID -ne 0 ]; then
    echo "Warning: running as non-root uid $UID"
    RUNAS_ID="$UID"
    RUNAS=""
else
    RUNAS_ID=${RUNAS_ID:-500}
    RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}

    # $RUNAS_ID may get set incorrectly somewhere else
    if [ $RUNAS_ID -eq 0 ]; then
        echo "Error: \$RUNAS_ID set to 0, but \$UID is also 0!"
        exit 1
    fi
fi

SANITYLOG=${SANITYLOG:-/tmp/sanity-gss.log}

export NAME=${NAME:-local}

SAVE_PWD=$PWD

#
# check pre-set $SEC
#
if [ ! -z $SEC ]; then
    if [ "$SEC" != "krb5i" -a "$SEC" != "krb5p" ]; then
        echo "SEC=$SEC is invalid, this script only run in gss mode (krb5i/krb5p)"
        exit 1
    fi
fi

export SEC=${SEC:-krb5p}
export KRB5_CCACHE_DIR=/tmp
export KRB5_CRED=$KRB5_CCACHE_DIR/krb5cc_$RUNAS_ID
export KRB5_CRED_SAVE=$KRB5_CCACHE_DIR/krb5cc.sanity.save

echo "Using security flavor $SEC"

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

prepare_krb5_creds() {
    rm -f $CRED_SAVE
    $RUNAS krb5_login.sh || exit 1
    [ -f $KRB5_CRED ] || exit 2
    cp $KRB5_CRED $KRB5_CRED_SAVE
}

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

trace() {
    log "STARTING: $*"
    strace -o $TMP/$1.strace -ttt $*
    RC=$?
    log "FINISHED: $*: rc $RC"
    return 1
}
TRACE=${TRACE:-""}

check_kernel_version() {
    VERSION_FILE=$LPROC/kernel_version
    WANT_VER=$1
    [ ! -f $VERSION_FILE ] && echo "can't find kernel version" && return 1
    GOT_VER=`cat $VERSION_FILE`
    [ $GOT_VER -ge $WANT_VER ] && return 0
    log "test needs at least kernel version $WANT_VER, running $GOT_VER"
    return 1
}

_basetest() {
    echo $*
}

[ "$SANITYLOG" ] && rm -f $SANITYLOG || true


prepare_krb5_creds
build_test_filter
umask 077

# setup filesystem
formatall
setupall
chmod a+rwx $MOUNT

restore_krb5_cred() {
    cp $KRB5_CRED_SAVE $KRB5_CRED
    chown $RUNAS_ID:$RUNAS_ID $KRB5_CRED
    chmod 0600 $KRB5_CRED
}

test_1() {
    # access w/o cred
    $RUNAS kdestroy
    $RUNAS touch $MOUNT/f1 && error "unexpected success"

    # access w/ cred
    restore_krb5_cred
    $RUNAS touch $MOUNT/f1 || error "should not fail"
    [ -f $MOUNT/f1 ] || error "$MOUNT/f1 not found"
}
run_test 1 "access with or without krb5 credential"

test_2() {
    # current access should be ok
    $RUNAS touch $MOUNT/f2_1 || error "can't touch $MOUNT/f2_1"
    [ -f $MOUNT/f2_1 ] || error "$MOUNT/f2_1 not found"

    # cleanup all cred/ctx and touch
    $RUNAS kdestroy
    $RUNAS $LFS flushctx
    $RUNAS touch $MOUNT/f2_2 && error "unexpected success"

    # restore and touch
    restore_krb5_cred
    $RUNAS touch $MOUNT/f2_2 || error "should not fail"
    [ -f $MOUNT/f2_2 ] || error "$MOUNT/f2_2 not found"
}
run_test 2 "lfs flushctx"

test_3() {
    local file=$MOUNT/f3

    # create file
    echo "aaaaaaaaaaaaaaaaa" > $file
    chmod 0666 $file
    $CHECKSTAT -p 0666 $file || error "$UID checkstat error"
    $RUNAS $CHECKSTAT -p 0666 $file || error "$RUNAS_ID checkstat error"
    $RUNAS cat $file > /dev/null || error "$RUNAS_ID cat error"

    # start multiop
    $RUNAS multiop $file o_r &
    OPPID=$!
    # wait multiop finish its open()
    sleep 1

    # cleanup all cred/ctx and check
    # metadata check should fail, but file data check should success
    # because we always use root credential to OSTs
    $RUNAS kdestroy
    $RUNAS $LFS flushctx
    $RUNAS $CHECKSTAT -p 0666 $file && error "checkstat succeed"
    kill -s 10 $OPPID
    wait $OPPID || error "read file data failed"
    echo "read file data OK"

    # restore and check again
    restore_krb5_cred
    $RUNAS $CHECKSTAT -p 0666 $file || error "$RUNAS_ID checkstat (2) error"
    $CHECKSTAT -p 0666 $file || error "$UID checkstat (2) error"
    $RUNAS cat $file > /dev/null || error "$RUNAS_ID cat (2) error"
}
run_test 3 "local cache under DLM lock"

test_4() {
    local file1=$MOUNT/f4_1
    local file2=$MOUNT/f4_2

    # current access should be ok
    $RUNAS touch $file1 || error "can't touch $file1"
    [ -f $file1 ] || error "$file1 not found"

    # stop lgssd
    send_sigint client lgssd
    sleep 5
    check_gss_daemon_facet client lgssd && error "lgssd still running"

    # flush context, and touch
    $RUNAS $LFS flushctx
    $RUNAS touch $file2 &
    TOUCHPID=$!
    echo "waiting touch pid $TOUCHPID"
    wait $TOUCHPID && error "touch should fail"

    # restart lgssd
    do_facet client "$LGSSD -v"
    sleep 5
    check_gss_daemon_facet client lgssd

    # touch new should succeed
    $RUNAS touch $file2 || error "can't touch $file2"
    [ -f $file2 ] || error "$file2 not found"
}
run_test 4 "lgssd dead, operations should wait timeout and fail"

test_5() {
    local file1=$MOUNT/f5_1
    local file2=$MOUNT/f5_2
    local wait_time=120

    # current access should be ok
    $RUNAS touch $file1 || error "can't touch $file1"
    [ -f $file1 ] || error "$file1 not found"

    # stop lsvcgssd
    send_sigint mds lsvcgssd
    sleep 5
    check_gss_daemon_facet mds lsvcgssd && error "lsvcgssd still running"

    # flush context, and touch
    $RUNAS $LFS flushctx
    $RUNAS touch $file2 &
    TOUCHPID=$!

    # wait certain time
    echo "waiting $wait_time seconds for touch pid $TOUCHPID"
    sleep $wait_time
    num=`ps --no-headers -p $TOUCHPID | wc -l`
    [ $num -eq 1 ] || error "touch already ended ($num)"
    echo "process $TOUCHPID still hanging there... OK"

    # restart lsvcgssd, expect touch suceed
    echo "restart lsvcgssd and recovering"
    do_facet mds "$LSVCGSSD -v"
    sleep 5
    check_gss_daemon_facet mds lsvcgssd
    wait $TOUCHPID || error "touch fail"
    [ -f $file2 ] || error "$file2 not found"
}
run_test 5 "lsvcgssd dead, operations lead to recovery"

test_6() {
    NPROC=`cat /proc/cpuinfo 2>/dev/null | grep ^processor | wc -l`
    [ $NPROC -ne 0 ] || NPROC=2

    echo "starting dbench $NPROC"
    sh rundbench $NPROC &
    RUNPID=$!

    for ((n=0;;n++)); do
        sleep 2
        num=`ps --no-headers -p $RUNPID | wc -l`
        [ $num -ne 0 ] || break
        echo "flush ctx ..."
        $LFS flushctx
    done
    wait $RUNPID || error "dbench detect error"
}
run_test 6 "recoverable from losing context"

check_multiple_gss_daemons() {
    local facet=$1

    for ((i=0;i<10;i++)); do
        do_facet $facet "$LSVCGSSD -v &"
    done
    for ((i=0;i<10;i++)); do
        do_facet $facet "$LGSSD -v &"
    done

    # wait daemons entering "stable" status
    sleep 5

    numc=`do_facet $facet ps -o cmd -C lgssd | grep lgssd | wc -l`
    nums=`do_facet $facet ps -o cmd -C lgssd | grep lgssd | wc -l`
    echo "$numc lgssd and $nums lsvcgssd are running"

    if [ $numc -ne 1 -o $nums -ne 1 ]; then
        error "lgssd/lsvcgssd not unique"
    fi
}

test_100() {
    local facet=mds

    # cleanup everything at first
    cleanupall

    echo "bring up gss daemons..."
    start_gss_daemons

    echo "check with someone already running..."
    check_multiple_gss_daemons $facet

    echo "check with someone run & finished..."
    do_facet $facet killall -q -2 lgssd lsvcgssd || true
    sleep 5 # wait fully exit
    check_multiple_gss_daemons $facet

    echo "check refresh..."
    do_facet $facet killall -q -2 lgssd lsvcgssd || true
    sleep 5 # wait fully exit
    do_facet $facet ipcrm -S 0x3b92d473
    do_facet $facet ipcrm -S 0x3a92d473
    check_multiple_gss_daemons $facet

    stop_gss_daemons
}
run_test 100 "start more multiple gss daemons"

TMPDIR=$OLDTMPDIR
TMP=$OLDTMP
HOME=$OLDHOME

log "cleanup: ======================================================"
if [ "`mount | grep ^$NAME`" ]; then
    rm -rf $DIR/[Rdfs][1-9]*
fi

cleanupall -f || error "cleanup failed"


echo '=========================== finished ==============================='
[ -f "$SANITYLOG" ] && cat $SANITYLOG && exit 1 || true
