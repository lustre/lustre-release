#!/bin/sh

set -ex

LUSTRE=${LUSTRE:-`dirname $0`/..}
PATH=$PATH:$LUSTRE/utils:$LUSTRE/tests

. $LUSTRE/../ltest/functional/llite/common/common.sh

PDSH='pdsh -w'

# XXX I wish all this stuff was in some default-config.sh somewhere
MDSNODE=${MDSNODE:-dev2}
OSTNODE=${OSTNODE:-dev3}
CLIENT=${CLIENTNODE:-dev4}
NETWORKTYPE=${NETWORKTYPE:-tcp}
MOUNTPT=${MOUNTPT:-/mnt/lustre}
CONFIG=recovery-small.xml
MDSDEV=/tmp/mds
OSTDEV=/tmp/ost
MDSSIZE=100000
OSTSIZE=100000

do_mds() {
    $PDSH $MDSNODE "PATH=\$PATH:$PATH; cd $PWD; $@"
}

do_client() {
    $PDSH $CLIENT "PATH=\$PATH:$PATH; cd $PWD; $@"
}

do_ost() {
    $PDSH $OSTNODE "PATH=\$PATH:$PATH; cd $PWD; $@"
}

drop_request() {
    do_mds "echo 0x121 > /proc/sys/lustre/fail_loc"
    do_client "$1"
    do_mds "echo 0 > /proc/sys/lustre/fail_loc"
}

drop_reply() {
    do_mds "echo 0x120 > /proc/sys/lustre/fail_loc"
    do_client "$@"
    do_mds "echo 0 > /proc/sys/lustre/fail_loc"
}

make_config() {
    rm -f $CONFIG
    for NODE in $CLIENT $MDSNODE $OSTNODE; do
       lmc -m $CONFIG --add net --node $NODE --nid `h2$NETWORKTYPE $NODE` \
           --nettype $NETWORKTYPE || exit 4
    done
    lmc -m $CONFIG --add mds --node $MDSNODE --mds mds1 --dev $MDSDEV \
        --size $MDSSIZE || exit 5
    lmc -m $CONFIG --add ost --node $OSTNODE --obd obd1 --dev $OSTDEV \
        --size $OSTSIZE || exit 6
    lmc -m $CONFIG --add mtpt --node $CLIENT --path $MOUNTPT --mds mds1 \
        --obd obd1 || exit 7
}

start_mds() {
    do_mds "lconf $@ $CONFIG"
}

shutdown_mds() {
    do_mds "lconf $@ --cleanup $CONFIG"
}

start_ost() {
    do_ost "lconf $@ $CONFIG"
}

shutdown_ost() {
    do_ost "lconf $@ --cleanup $CONFIG"
}

mount_client() {
    do_client "lconf $@ $CONFIG"
}

unmount_client() {
    do_client "lconf $@ --cleanup $CONFIG"
}

setup() {
    make_config
    start_mds --reformat
    start_ost --reformat
    # XXX we should write our own upcall, when we move this somewhere better.
    mount_client --timeout=10 \
        --recovery_upcall=$PWD/../../ltest/functional/llite/09/client-upcall.sh
}

cleanup() {
    unmount_client
    shutdown_mds
    shutdown_ost
}

replay() {
    if [ $# -gt 1 ]; then
        do_client "$1"
        shift
    fi
    do_mds "sync"
    echo -e 'device $mds1\nreadonly' | do_mds "lctl"
    do_client "$1" &
    shutdown_mds -f
    start_mds
    wait
}

setup
drop_request "mcreate /mnt/lustre/1"
drop_reply "mcreate /mnt/lustre/2"
replay "mcreate /mnt/lustre/3"
