#!/bin/sh

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
LTESTDIR=${LTESTDIR:-$LUSTRE/../ltest}
PATH=$PATH:$LUSTRE/utils:$LUSTRE/tests

RLUSTRE=${RLUSTRE:-$LUSTRE}
RPWD=${RPWD:-$PWD}

. $LTESTDIR/functional/llite/common/common.sh

# XXX I wish all this stuff was in some default-config.sh somewhere
MOUNT=${MOUNT:-/mnt/lustre}
MDSDEV=${MDSDEV:-/tmp/mds-`hostname`}
MDSSIZE=${MDSSIZE:-100000}
OSTDEV=${OSTDEV:-/tmp/ost-`hostname`}
OSTSIZE=${OSTSIZE:-100000}
MOUNT=${MOUNT:-/mnt/lustre}
MOUNT1=${MOUNT1:-${MOUNT}1}
MOUNT2=${MOUNT2:-${MOUNT}2}
UPCALL=${UPCALL:-$PWD/replay-single-upcall.sh}
FSTYPE=${FSTYPE:-ext3}
TIMEOUT=${TIMEOUT:-5}

start() {
    facet=$1
    shift
    lconf --node ${facet}_facet $@ replay-dual.xml
}

stop() {
    facet=$1
    shift
    lconf --node ${facet}_facet $@ -d replay-dual.xml
}

replay_barrier() {
    local dev=$1
    sync
    lctl --device %${dev}1 readonly
    lctl --device %${dev}1 notransno
}

fail() {
    stop mds
    start mds
    df $MOUNT1 | tail -1
    df $MOUNT2 | tail -1
}

do_lmc() {
    lmc -m replay-dual.xml $@
}

add_facet() {
    local facet=$1
    shift
    do_lmc --add node --node ${facet}_facet $@ --timeout $TIMEOUT
    do_lmc --add net --node ${facet}_facet --nid localhost --nettype tcp
}

gen_config() {
    rm -f replay-dual.xml
    add_facet mds
    add_facet ost
    add_facet client1 --lustre_upcall $UPCALL
    add_facet client2 --lustre_upcall $UPCALL
    do_lmc --add mds --node mds_facet --mds mds1 --dev $MDSDEV --size $MDSSIZE
    do_lmc --add ost --node ost_facet --ost ost1 --dev $OSTDEV --size $OSTSIZE
    do_lmc --add mtpt --node client1_facet --path $MOUNT1 --mds mds1 --ost ost1
    do_lmc --add mtpt --node client1_facet --path $MOUNT2 --mds mds1 --ost ost1
}

gen_config
start mds
start ost
start client1
start client2

touch $MOUNT1/lustre-works
replay_barrier mds
touch $MOUNT2/lustre-does-not-work

stop client2
stop client1
stop ost
stop mds

start mds
start ost
start client1
start client2

if [ -e $MOUNT1/lustre-does-not-work ]; then
	echo "$MOUNT1/lustre-does-not-work exists"
	exit 1
fi

stop client2
stop client1
stop ost
stop mds
