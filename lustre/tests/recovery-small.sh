#!/bin/sh

set -ex

LUSTRE=${LUSTRE:-`dirname $0`/..}
LTESTDIR=${LTESTDIR:-$LUSTRE/../ltest}
PATH=$PATH:$LUSTRE/utils:$LUSTRE/tests

RLUSTRE=${RLUSTRE:-$LUSTRE}
RPWD=${RPWD:-$PWD}

. $LTESTDIR/functional/llite/common/common.sh

# Allow us to override the setup if we already have a mounted system by
# setting SETUP=" " and CLEANUP=" "
SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

PDSH=${PDSH:-'pdsh -S -w'}

# XXX I wish all this stuff was in some default-config.sh somewhere
MDSNODE=${MDSNODE:-mdev6}
OSTNODE=${OSTNODE:-mdev7}
CLIENT=${CLIENT:-mdev8}
NETWORKTYPE=${NETWORKTYPE:-tcp}
MOUNTPT=${MOUNTPT:-/mnt/lustre}
CONFIG=${CONFIG:-recovery-small.xml}
MDSDEV=${MDSDEV:-/tmp/mds}
OSTDEV=${OSTDEV:-/tmp/ost}
MDSSIZE=${MDSSIZE:-100000}
OSTSIZE=${OSTSIZE:-100000}
UPCALL=${UPCALL:-$LTESTDIR/functional/llite/09/client-upcall.sh}

do_mds() {
    $PDSH $MDSNODE "PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests; cd $RPWD; $@" || exit $?
}

do_client() {
    $PDSH $CLIENT "PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests; cd $RPWD; $@"  || exit $?
}

do_ost() {
    $PDSH $OSTNODE "PATH=\$PATH:$RLUSTRE/utils:$RLUSTRE/tests; cd $RPWD; $@" || exit $?
}

drop_request() {
# OBD_FAIL_MDS_ALL_REQUEST_NET
    do_mds "echo 0x121 > /proc/sys/lustre/fail_loc"
    do_client "$1"
    do_mds "echo 0 > /proc/sys/lustre/fail_loc"
}

drop_reply() {
# OBD_FAIL_MDS_ALL_REPLY_NET
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
    lmc -m $CONFIG --add ost --node $OSTNODE --ost ost1 --dev $OSTDEV \
        --size $OSTSIZE || exit 6
    lmc -m $CONFIG --add mtpt --node $CLIENT --path $MOUNTPT --mds mds1 \
        --ost ost1 || exit 7
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
    start_mds ${REFORMAT}
    start_ost ${REFORMAT}
    # XXX we should write our own upcall, when we move this somewhere better.
    mount_client --timeout=${TIMEOUT:-5} \
        --lustre_upcall=$UPCALL
}

cleanup() {
    do_mds "echo 0 > /proc/sys/lustre/fail_loc"
    unmount_client $@ || true
    shutdown_mds $@ || true
    shutdown_ost $@ || true
}

replay() {
    do_mds "sync"
    do_mds 'echo -e "device \$mds1\\nprobe\\nnotransno\\nreadonly" | lctl'
    do_client "$1" &
    shutdown_mds -f
    start_mds
    wait
    do_client "df -h $MOUNTPT" # trigger failover, if we haven't already
}

if [ ! -z "$ONLY" ]; then
    eval "$ONLY"
    exit $?
fi

make_config

REFORMAT=--reformat $SETUP
unset REFORMAT

drop_request "mcreate /mnt/lustre/1"
drop_reply "mcreate /mnt/lustre/2"
# replay "mcreate /mnt/lustre/3"

drop_request "tchmod 111 /mnt/lustre/2"
drop_reply "tchmod 666 /mnt/lustre/2"
# replay "tchmod 444 /mnt/lustre/2"

drop_request "statone /mnt/lustre/2"
drop_reply "statone /mnt/lustre/2"
# replay "statone /mnt/lustre/2"

do_client "cp /etc/resolv.conf /mnt/lustre/resolv.conf"
drop_request "cat /mnt/lustre/resolv.conf > /dev/null"
drop_reply "cat /mnt/lustre/resolv.conf > /dev/null"

drop_request "mv /mnt/lustre/resolv.conf /mnt/lustre/renamed"
drop_reply "mv /mnt/lustre/renamed /mnt/lustre/renamed-again"

drop_request "mlink /mnt/lustre/renamed-again /mnt/lustre/link1"
drop_reply "mlink /mnt/lustre/renamed-again /mnt/lustre/link2"

drop_request "munlink /mnt/lustre/link1"
drop_reply "munlink /mnt/lustre/link2"

$CLEANUP
