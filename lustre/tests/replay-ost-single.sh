#!/bin/sh

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env

# XXX I wish all this stuff was in some default-config.sh somewhere
mds_HOST=${mds_HOST:-`hostname`}
ost_HOST=${ost_HOST:-`hostname`}
ostfailover_HOST=${ostfailover_HOST}
client_HOST=${client_HOST:-`hostname`}

NETTYPE=${NETTYPE:-tcp}

PDSH=${PDSH:-no_dsh}
MOUNT=${MOUNT:-/mnt/lustre}
DIR=${DIR:-$MOUNT}
MDSDEV=${MDSDEV:-/tmp/mds-`hostname`}
MDSSIZE=${MDSSIZE:-100000}
OSTDEV=${OSTDEV:-/tmp/ost-`hostname`}
OSTFAILOVERDEV=${OSTFAILOVERDEV:-$OSTDEV}
OSTSIZE=${OSTSIZE:-100000}
UPCALL=${UPCALL:-$PWD/replay-ost-upcall.sh}
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
    if [ ! -z "$ostfailover_HOST" ]; then
	add_facet ostfailover
        do_lmc --add ost --lov lov1 --node ostfailover_facet --ost ost1 --dev $OSTFAILOVERDEV --size $OSTSIZE
    fi
    do_lmc --add mtpt --node client_facet --path $MOUNT --mds mds1 --ost lov1
}

cleanup() {
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activeost=`facet_active ost`
    if [ $activeost != "ost" ]; then
        fail ost
    fi
    zconf_umount $MOUNT
    stop mds ${FORCE} $MDSLCONFARGS
    stop ost ${FORCE} --dump cleanup.log
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0
    cleanup
    exit
fi

build_test_filter

rm ostactive

gen_config

start ost --reformat $OSTLCONFARGS
PINGER=`cat /proc/fs/lustre/pinger`

if [ "$PINGER" != "on" ]; then
    echo "ERROR: Lustre must be built with --enable-pinger for replay-dual"
    stop ost
    exit 1
fi
start mds --reformat $MDSLCONFARGS
zconf_mount $MOUNT

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

