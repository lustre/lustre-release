#!/bin/sh

set -e

#
# This test needs to be run on the client
#

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/lmv.sh}

# Skip these tests
ALWAYS_EXCEPT=""


gen_config() {
    rm -f $XMLCONFIG

    if [ "$MDSCOUNT" -gt 1 ]; then
        add_lmv lmv1
        for num in `seq $MDSCOUNT`; do
            MDSDEV=$TMP/mds${num}-`hostname`
            add_mds mds$num --dev $MDSDEV --size $MDSSIZE --lmv lmv1
        done
        add_lov_to_lmv lov1 lmv1 --stripe_sz $STRIPE_BYTES \
	    --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
        add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE
        add_ost ost2 --lov lov1 --dev ${OSTDEV}-2 --size $OSTSIZE
        add_client client --lmv lmv1 --lov lov1 --path $MOUNT
    else
        add_mds mds1 --dev $MDSDEV --size $MDSSIZE
        if [ ! -z "$mdsfailover_HOST" ]; then
	     add_mdsfailover mds --dev $MDSDEV --size $MDSSIZE
        fi

        add_lov lov1 mds1 --stripe_sz $STRIPE_BYTES \
	    --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
        add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE
        add_ost ost2 --lov lov1 --dev ${OSTDEV}-2 --size $OSTSIZE
        add_client client --mds mds1_svc --lov lov1 --path $MOUNT
    fi
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
    if [ "$MDSCOUNT" -gt 1 ]; then
        for num in `seq $MDSCOUNT`; do
            stop mds$num ${FORCE} $MDSLCONFARGS
        done
    else
        stop mds ${FORCE} $MDSLCONFARGS
    fi
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
    start mds1 $MDSLCONFARGS --reformat
    start mds2 $MDSLCONFARGS --reformat
    start mds3 $MDSLCONFARGS --reformat
    grep " $MOUNT " /proc/mounts || zconf_mount `hostname` $MOUNT
}

$SETUP

if [ "$ONLY" == "setup" ]; then
    exit 0
fi

mkdir -p $DIR

test_0() {
    replay_barrier mds1
    fail mds1
}
run_test 0 "empty replay"

test_0b() {
    # this test attempts to trigger a race in the precreation code, 
    # and must run before any other objects are created on the filesystem
    fail ost
    createmany -o $DIR/$tfile 20 || return 1
    unlinkmany $DIR/$tfile 20 || return 2
}
run_test 0b "ensure object created after recover exists. (3284)"

test_1a() {
    mkdir $DIR/dir01
    replay_barrier mds2
    $CHECKSTAT -t dir $DIR/dir01 || return 1
    rmdir $DIR/dir01
    fail mds2
    stat $DIR/dir01
}
run_test 1a "unlink cross-node dir (fail mds with inode)"

test_1b() {
    mkdir $DIR/dir11
    replay_barrier mds1
    $CHECKSTAT -t dir $DIR/dir11 || return 1
    rmdir $DIR/dir11
    fail mds1
    stat $DIR/dir11
}
run_test 1b "unlink cross-node dir (fail mds with name)"

test_2a() {
    mkdir $DIR/dir21
    createmany -o $DIR/dir21/f 3000
    sleep 10
    $CHECKSTAT -t dir $DIR/dir21 || return 1
    $CHECKSTAT -t file $DIR/dir21/f1002 || return 1
    replay_barrier mds1
    rm $DIR/dir21/f1002
    fail mds1
    stat $DIR/dir21/f1002
}
run_test 2a "unlink cross-node file (fail mds with name)"


test_3a() {
    replay_barrier mds2
    mkdir $DIR/dir3a1
    $LCTL mark "FAILOVER mds2"
    fail mds2
    stat $DIR
    $CHECKSTAT -t dir $DIR/dir3a1 || return 1
}
run_test 3a "mkdir cross-node dir (fail mds with inode)"

test_3b() {
    mkdir $DIR/dir13
    replay_barrier mds1
    $CHECKSTAT -t dir $DIR/dir13 || return 1
    rmdir $DIR/dir13
    fail mds1
    stat $DIR/dir13
}
run_test 3b "mkdir cross-node dir (fail mds with name)"

equals_msg test complete, cleaning up
$CLEANUP

