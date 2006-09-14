#!/bin/sh

set -ex

LUSTRE=${LUSTRE:-`dirname $0`/..}
LTESTDIR=${LTESTDIR:-"$LUSTRE/../ltest"}
PATH=$PATH:$LUSTRE/utils:$LUSTRE/tests

. $LTESTDIR/functional/llite/common/common.sh

# Allow us to override the setup if we already have a mounted system by
# setting SETUP=" " and CLEANUP=" "
SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

PDSH='pdsh -S -w'

# XXX I wish all this stuff was in some default-config.sh somewhere
MDSNODE=${MDSNODE:-mdev6}
OSTNODE=${OSTNODE:-mdev7}
CLIENT=${CLIENT:-mdev8}
NETTYPE=${NETTYPE:-tcp}
MOUNTPT=${MOUNTPT:-/mnt/lustre}
CONFIG=${CONFIG:-recovery-cleanup.xml}
MDSDEV=${MDSDEV:-/tmp/mds1-`hostname`}
MDSSIZE=${MDSSIZE:-100000}
FSTYPE=${FSTYPE:-ext3}
OSTDEV=${OSTDEV:-/tmp/ost1-`hostname`}
OSTSIZE=${OSTSIZE:-100000}
STRIPE_BYTES=${STRIPE_BYTES:-1048576}

do_mds() {
    $PDSH $MDSNODE "PATH=\$PATH:$LUSTRE/utils:$LUSTRE/tests; cd $PWD; $@" || exit $?
}

do_client() {
    $PDSH $CLIENT "PATH=\$PATH:$LUSTRE/utils:$LUSTRE/tests; cd $PWD; $@" || exit $?
}

do_ost() {
    $PDSH $OSTNODE "PATH=\$PATH:$LUSTRE/utils:$LUSTRE/tests; cd $PWD; $@" || exit $?
}

drop_request() {
    do_mds "echo 0x121 > /proc/sys/lustre/fail_loc"
    do_client "$1 & sleep ${TIMEOUT:-5}; sleep 2; kill \$!"
    do_mds "echo 0 > /proc/sys/lustre/fail_loc"
}

make_config() {
    rm -f $CONFIG
    for NODE in $CLIENT $MDSNODE $OSTNODE; do
       lmc -m $CONFIG --add net --node $NODE --nid `h2$NETTYPE $NODE` \
           --nettype $NETTYPE || exit 4
    done
    lmc -m $CONFIG --add mds --node $MDSNODE --mds mds1 --fstype $FSTYPE \
    	--dev $MDSDEV --size $MDSSIZE || exit 5
    lmc -m $CONFIG --add lov --lov lov1 --mds mds1 --stripe_sz $STRIPE_BYTES \
        --stripe_cnt 0 --stripe_pattern 0 || exit 6
    lmc -m $CONFIG --add ost --nspath /mnt/ost_ns --node $OSTNODE \
        --lov lov1 --dev $OSTDEV --size $OSTSIZE --fstype $FSTYPE || exit 7
    lmc -m $CONFIG --add mtpt --node $CLIENT --path $MOUNTPT \
        --mds mds1 --lov lov1 || exit 8
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
    start_mds ${REFORMAT:---reformat}
    start_ost ${REFORMAT:---reformat}
    mount_client --timeout=${TIMEOUT:-5} --lustre_upcall=/bin/true
}

cleanup() {
    do_mds "echo 0 > /proc/sys/lustre/fail_loc"
    unmount_client $@ || exit 97
    shutdown_mds $@ || exit 98
    shutdown_ost $@ || exit 99
}

wait_for_timeout() {
    # wait to make sure we enter recovery
    # it'd be better if the upcall notified us somehow, I think
    sleep $(( ${TIMEOUT:-5} + 2 ))
}

try_to_cleanup() {
    kill -INT $!
    unmount_client --force --dump $TMP/recovery-cleanup-`hostname`.log
    mount_client --timeout=${TIMEOUT:-5} --lustre_upcall=/bin/true
}

if [ ! -z "$ONLY" ]; then
    eval "$ONLY"
    exit $?
fi

$SETUP

drop_request "mcreate /mnt/lustre/1" & wait_for_timeout
try_to_cleanup

drop_request "tchmod 111 /mnt/lustre/2" & wait_for_timeout
try_to_cleanup

drop_request "statone /mnt/lustre/2" & wait_for_timeout
try_to_cleanup

do_client "cp /etc/inittab /mnt/lustre/inittab"
drop_request "cat /mnt/lustre/inittab > /dev/null" & wait_for_timeout
try_to_cleanup

drop_request "mv /mnt/lustre/inittab /mnt/lustre/renamed" & wait_for_timeout
try_to_cleanup

drop_request "mlink /mnt/lustre/renamed-again /mnt/lustre/link1" & wait_for_timeout
try_to_cleanup

drop_request "munlink /mnt/lustre/link1" & wait_for_timeout
try_to_cleanup

FORCE=--force $CLEANUP '--dump $TMP/recovery-cleanup-`hostname`.log'
