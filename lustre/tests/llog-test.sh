#!/bin/sh

set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

ostfailover_HOST=${ostfailover_HOST:-$ost_HOST}

gen_config() {
    rm -f "$XMLCONFIG"
    add_mds mds --dev "$MDSDEV" --size "$MDSSIZE"
    add_lov lov1 mds --stripe_sz $STRIPE_BYTES \
	--stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
    add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE --failover
    if [ ! -z "$ostfailover_HOST" ]; then
	 add_ostfailover ost --dev $OSTDEV --size $OSTSIZE
    fi
    add_client client mds --lov lov1 --path $MOUNT
}

cleanup() {
    # make sure we are using the primary MDS, so the config log will
    # be able to clean up properly.
    activeost=`facet_active ost`
    if [ $activeost != "ost" ]; then
        fail ost
    fi
    zconf_umount `hostname` $MOUNT
    stop mds ${FORCE} $MDSLCONFARGS
    stop ost ${FORCE} --dump $TMP/replay-ost-single-`hostname`.log
    cleanup_check
}

if [ "$ONLY" == "cleanup" ]; then
    sysctl -w portals.debug=0
    FORCE=--force cleanup
    exit
fi

build_test_filter

SETUP=${SETUP:-"setup"}
CLEANUP=${CLEANUP:-"cleanup"}

setup() {
    gen_config

    start ost --reformat $OSTLCONFARGS
    [ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE
    start mds --reformat $MDSLCONFARGS

    if [ -z "`grep " $MOUNT " /proc/mounts`" ]; then
	# test "-1" needed during initial client->OST connection
	log "== test 00: target handle mismatch (bug 5317) === `date +%H:%M:%S`"

	#define OBD_FAIL_OST_ALL_REPLY_NET       0x211
	do_facet ost1 "lctl set_param fail_loc=0x80000211"

	zconf_mount `hostname` $MOUNT && df $MOUNT && pass || error "mount fail"
    fi
}

mkdir -p $DIR

$SETUP

LCOUNT=${LCOUNT:-10000}

test_0() {
    ./createmany -o $DIR/llog-%d $LCOUNT
    #replay_barrier ost
}
run_test 0 "Prepare fileset"

test_1() {
    ./chownmany 1000 $DIR/llog-%d $LCOUNT
    sleep 5
    $CHECKSTAT -u \#1000 $DIR/llog-* || return 4
}
run_test 1 "Do chowns"

test_2() {
    HALFCOUNT=${HALFCOUNT:-17}
    ./chownmany 500 $DIR/llog-%d 0 $HALFCOUNT
    fail ost
    ./chownmany 500 $DIR/llog-%d $HALFCOUNT $LCOUNT
    sleep 5
    $CHECKSTAT -u \#500 $DIR/llog-* || return 5
}
run_test 2 "Fail OST during chown"

test_3() {
    ./unlinkmany $DIR/llog-%d $LCOUNT
    sleep 2
    $CHECKSTAT -t file $DIR/llog-* && return 10 || true
}
run_test 3 "Remove testset"

equals_msg test complete, cleaning up
FORCE=--force $CLEANUP
echo "$0: completed"
