#!/bin/sh

set -e

# Skip these tests
# 3 - bug 1852
ALWAYS_EXCEPT="3"

LCONF=${LCONF:-"../utils/lconf"}
LMC=${LMC:-"../utils/lmc"}
LCTL=${LCTL:-"../utils/lctl"}
LUSTRE=${LUSTRE:-`dirname $0`/..}
LTESTDIR=${LTESTDIR:-$LUSTRE/../ltest}
PATH=$LUSTRE/utils:$LUSTRE/tests:$PATH

RLUSTRE=${RLUSTRE:-$LUSTRE}
RPWD=${RPWD:-$PWD}

XMLCONFIG="`basename $0 .sh`.xml"

. $LUSTRE/tests/test-framework.sh

CHECKSTAT="${CHECKSTAT:-checkstat} -v"

# XXX I wish all this stuff was in some default-config.sh somewhere
MOUNT=${MOUNT:-/mnt/lustre}
DIR=${DIR:-$MOUNT}
MDSDEV=${MDSDEV:-/tmp/mds-`hostname`}
MDSSIZE=${MDSSIZE:-100000}
OSTDEV=${OSTDEV:-/tmp/ost-`hostname`}
OSTSIZE=${OSTSIZE:-100000}
UPCALL=${UPCALL:-$PWD/replay-single-upcall.sh}
FSTYPE=${FSTYPE:-ext3}
TIMEOUT=${TIMEOUT:-5}

STRIPE_BYTES=65536
STRIPES_PER_OBJ=1


gen_config() {
    rm -f $XMLCONFIG
    add_facet mds
    add_facet ost
    add_facet client --lustre_upcall $UPCALL
    do_lmc --add mds --node mds_facet --mds mds1 --dev $MDSDEV --size $MDSSIZE
    do_lmc --add lov --mds mds1 --lov lov1 --stripe_sz $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
    do_lmc --add ost --lov lov1 --failover --node ost_facet --ost ost1 --dev $OSTDEV --size $OSTSIZE
    do_lmc --add mtpt --node client_facet --path $MOUNT --mds mds1 --ost lov1
}


build_test_filter

gen_config
start mds --reformat $MDSLCONFARGS
start ost --reformat $OSTLCONFARGS
start client --gdb $CLIENTLCONFARGS

mkdir -p $DIR

test_0() {
    replay_barrier ost
    fail ost
}
run_test 0 "empty replay"

test_1() {
    replay_barrier ost
    touch $DIR/$tfile
    fail ost
    $CHECKSTAT -t file $DIR/$tfile || return 1
}
run_test 1 "touch"

test_2() {
    replay_barrier ost
    for i in `seq 10`; do
        echo "tag-$i" > $DIR/$tfile-$i
    done 
    fail ost
    for i in `seq 10`; do
      grep -q "tag-$i" $DIR/$tfile-$i || error "f1c-$i"
    done 
}
run_test 2 "|x| 10 open(O_CREAT)s"

exit 0

equals_msg test complete, cleaning up
stop client ${FORCE:=--force} $CLIENTLCONFARGS
stop ost ${FORCE}
stop mds ${FORCE} $MDSLCONFARGS --dump cleanup.log

