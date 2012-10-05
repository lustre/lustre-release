#!/bin/bash

set -e
#set -v

#
# This test needs to be run on the client
#

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/lmv.sh}


# Skip these tests
ALWAYS_EXCEPT=""
build_test_filter

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"stopall"}

if [ "$ONLY" == "cleanup" ]; then
    lctl set_param debug=0 || true
    $CLEANUP
    exit 0
fi

setup() {
    formatall
    setupall
}

$SETUP

if [ "$ONLY" == "setup" ]; then
    exit 0
fi

mkdir -p $DIR

# LU-482 Avert LVM and VM inability to flush caches in pre .33 kernels
if [ $LINUX_VERSION_CODE -lt $(version_code 2.6.33) ]; then
    sync
    do_facet $SINGLEMDS sync
fi

test_0() {
    replay_barrier mds1
    fail mds1
}
run_test 0 "empty replay"

test_0b() {
    # this test attempts to trigger a race in the precreation code, 
    # and must run before any other objects are created on the filesystem
    fail ost1
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
    replay_barrier mds1
    mkdir $DIR/dir3b1
    $LCTL mark "FAILOVER mds1"
    fail mds1
    stat $DIR
    $CHECKSTAT -t dir $DIR/dir3b1 || return 1
}
run_test 3b "mkdir cross-node dir (fail mds with inode)"

complete $SECONDS
$CLEANUP

