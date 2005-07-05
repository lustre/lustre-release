#!/bin/sh

set -e

#
# This test needs to be run on the client
#

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

# Skip these tests
ALWAYS_EXCEPT="1 3"

gen_config() {
    rm -f $XMLCONFIG
    add_mds mds --dev $MDSDEV --size $MDSSIZE
    if [ ! -z "$mdsfailover_HOST" ]; then
	 add_mdsfailover mds --dev $MDSDEV --size $MDSSIZE
    fi
    
    add_lov lov1 mds --stripe_sz $STRIPE_BYTES \
	--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
    add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE
    add_ost ost2 --lov lov1 --dev ${OSTDEV}-2 --size $OSTSIZE
    add_client client mds --lov lov1 --path $MOUNT
}

build_test_filter

cleanup() {
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activemds=`facet_active mds`
    if [ $activemds != "mds" ]; then
        fail mds
    fi
    zconf_umount `hostname` $MOUNT
    stop mds ${FORCE} $MDSLCONFARGS
    stop ost2 ${FORCE} --dump cleanup.log
    stop ost ${FORCE} --dump cleanup.log
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0 || true
    cleanup
    exit
fi

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

setup() {
    gen_config

    start ost --reformat $OSTLCONFARGS 
    start ost2 --reformat $OSTLCONFARGS 
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    start mds $MDSLCONFARGS --reformat
    grep " $MOUNT " /proc/mounts || zconf_mount `hostname` $MOUNT
}

$SETUP

if [ "$ONLY" == "setup" ]; then
    exit 0
fi

mkdir -p $DIR
 
# bug 3488 - test MDS replay more intensely
test_1() {
    sh rundbench 2 &
    pid=$!
    sleep 3
    replay_barrier mds
    sleep 2
    fail mds
    wait $PID || return 1
}
run_test 1 "fail MDS during dbench"

test_2() {
    mkdir $DIR/$tdir
    bonnie++ -u root -d $DIR/$tdir -s 0 -n 1 &
    pid=$!
    sleep 3
    replay_barrier mds
    sleep 2
    fail mds
    wait $PID || return 1
    rm -rf $DIR/root
}
run_test 2 "fail MDS during bonnie++"

if [ $UID -ne 0 ]; then
        RUNAS_ID="$UID"
        RUNAS=""
else
        RUNAS_ID=${RUNAS_ID:-500}
        if [ -z "$RUNAS_GID" ]; then
	    RUNAS=${RUNAS:-"runas -u $RUNAS_ID"}
        else
	    RUNAS=${RUNAS:-"runas -u $RUNAS_ID -g $RUNAS_GID"}
        fi
fi

OLDTMPDIR=$TMPDIR
OLDTMP=$TMP
TMPDIR=/tmp
TMP=/tmp
OLDHOME=$HOME
[ $RUNAS_ID -ne $UID ] && HOME=/tmp
                                                                                                                             
test_3() {
    cvsroot=$DIR/${tdir}-csvroot
    repos=${tdir}-repos
    mkdir -p $cvsroot
    chown $RUNAS_ID $cvsroot
    $RUNAS cvs -d $cvsroot init || error

    cd /etc/init.d
    # some versions of cvs import exit(1) when asked to import links or
    # files they can't read.  ignore those files.
    TOIGNORE=$(find . -type l -printf '-I %f\n' -o \
                    ! -perm +4 -printf '-I %f\n')
    $RUNAS cvs -d $cvsroot import -m "nomesg" $TOIGNORE \
            $repos vtag rtag

    cd $DIR
	mkdir -p $DIR/$repos
    chown $RUNAS_ID $DIR/$repos
    $RUNAS cvs -d $cvsroot co $repos

    cd $DIR/$repos

    for i in `seq 1 20`; do
        $RUNAS touch ${tfile}-$i
        $RUNAS cvs add -m 'addmsg' ${tfile}-$i
    done

    replay_barrier mds
    $RUNAS cvs update
    $RUNAS cvs commit -m 'nomsg' ${tfile}-*
    cd $LUSTRE
    fail mds
}
run_test 3 "fail MDS during cvs commit"

TMPDIR=$OLDTMPDIR
TMP=$OLDTMP
HOME=$OLDHOME

test_4() {
    touch $DIR/$tfile-1
    ln $DIR/$tfile-1 $DIR/$tfile-2 || return 1

    replay_barrier mds
    multiop $DIR/$tfile-2 Ouc
    fail mds

    $CHECKSTAT -t file $DIR/$tfile-1 || return 2
    rm -rf $DIR/$tfile-*
}
run_test 4 "|X| unlink file with multiple links while open"

test_5() {
    replay_barrier mds
    touch $DIR/$tfile-1
    ln $DIR/$tfile-1 $DIR/$tfile-2 || return 1
    multiop $DIR/$tfile-2 Ouc

    fail mds

    $CHECKSTAT -t file $DIR/$tfile-1 || return 2
    rm -rf $DIR/$tfile-*
}
run_test 5 "|X| unlink file with multiple links while open"

test_6() {
    touch $DIR/$tfile-1
    ln $DIR/$tfile-1 $DIR/$tfile-2

    replay_barrier mds
    multiop $DIR/$tfile-1 O_uc &
    MULTIPID=$!
    multiop $DIR/$tfile-2 Ouc
    usleep 500
    fail mds

    kill -USR1 $MULTIPID
    wait $MUTLIPID || return 1

    [ -e $DIR/$tfile-1 ] && return 2
    [ -e $DIR/$tfile-2 ] && return 3
    return 0
}
run_test 6 "|X| open-unlink file with multiple links"

test_7() {
    replay_barrier mds
    touch $DIR/$tfile-1
    ln $DIR/$tfile-1 $DIR/$tfile-2
    multiop $DIR/$tfile-1 O_uc &
    MULTIPID=$!

    multiop $DIR/$tfile-2 Ouc
    usleep 500

    kill -USR1 $MULTIPID
    wait $MUTLIPID || return 1
    fail mds

    [ -e $DIR/$tfile-1 ] && return 2
    [ -e $DIR/$tfile-2 ] && return 3
    return 0
}
run_test 7 "|X| open-unlink file with multiple links"

test_8() {
    replay_barrier mds
    opendirunlink $DIR/$tdir $DIR/$tdir || return 1
    fail mds
    $CHECKSTAT -a $DIR/$tdir || return 2
}
run_test 8 "|X| remove of open directory"

check_kernel_version() {
    VERSION_FILE=/proc/fs/lustre/kernel_version
    WANT_VER=$1
    [ ! -f $VERSION_FILE ] && echo "can't find kernel version" && return 1
    GOT_VER=`cat $VERSION_FILE`
    [ $GOT_VER -ge $WANT_VER ] && return 0
    log "test needs at least kernel version $WANT_VER, running $GOT_VER"
    return 1
}

test_9() {
    check_kernel_version 34 || return 0
    replay_barrier mds
    openfilleddirunlink $DIR/$tdir || return 1
    fail mds
}
run_test 9 "|X| remove of open non-empty directory"

equals_msg test complete, cleaning up
$CLEANUP
 
