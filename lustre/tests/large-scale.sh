#!/bin/bash

set -e

# bug number:
ALWAYS_EXCEPT="$LARGE_SCALE_EXCEPT"

SAVE_PWD=$PWD
PTLDEBUG=${PTLDEBUG:--1}
LUSTRE=${LUSTRE:-`dirname $0`/..}
SETUP=${SETUP:-""}
CLEANUP=${CLEANUP:-""}
. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

remote_mds_nodsh && log "SKIP: remote MDS with nodsh" && exit 0

[ -n "$CLIENTS" ] || { skip "$0: Need two or more clients" && exit 0; }
[ $CLIENTCOUNT -ge 2 ] || \
    { skip "$0: Need two or more clients, have $CLIENTCOUNT" && exit 0; }

#
[ "$SLOW" = "no" ] && EXCEPT_SLOW=""

MOUNT_2=""
build_test_filter

check_and_setup_lustre
rm -rf $DIR/[df][0-9]*

[ "$DAEMONFILE" ] && $LCTL debug_daemon start $DAEMONFILE $DAEMONSIZE

# VBR scale tests
check_vbr () {
    do_nodes $CLIENTS "$LCTL get_param mdc.*.connect_flags | grep version_recovery" 
}

check_vbr || \
    { skip "$0: no version_recovery" && exit 0; }

FAKE_NUM_MAX=${FAKE_NUM_MAX:-1000}
[ "$SLOW" = "no" ] && FAKE_NUM_MAX=100

do_and_time () {
   local cmd=$1

   local start_ts=`date +%s`

   $cmd

   local current_ts=`date +%s`
   ELAPSED=`expr $current_ts - $start_ts`
   echo "===== START $start_ts CURRENT $current_ts"
}

delete_fake_exports () {
    NUM=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_exports|wc -l")

    OLD_AGE=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_export_age")
    NEW_AGE=0
    do_facet mds "lctl set_param mds.${mds_svc}.stale_export_age=$NEW_AGE"
    sleep $((NEW_AGE + 3))
    EX_NUM=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_exports|grep -c EXPIRED")
    [ "$EX_NUM" -eq "$NUM" ] || error "not all exports are expired $EX_NUM != $NUM"

    do_facet mds "lctl set_param mds.${mds_svc}.flush_stale_exports=1"
    do_facet mds "lctl set_param mds.${mds_svc}.stale_export_age=$OLD_AGE"
}

test_1b() {
    local FAKE_NUM
    local NUM

    for FAKE_NUM in 10 $FAKE_NUM_MAX; do
        zconf_umount_clients $CLIENTS $DIR
        zconf_mount $CLIENT1 $DIR

        NUM=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_exports|wc -l")

        log "===== CREATE FAKE EXPORTS: $FAKE_NUM ( were $NUM )"
        create_fake_exports mds $FAKE_NUM
        NUM=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_exports|wc -l")
        [ $NUM -lt $FAKE_NUM ] && error "fake exports $NUM -ne $FAKE_NUM"
        echo "===== STALE EXPORTS: FAKE_NUM=$FAKE_NUM NUM=$NUM"
        do_and_time "zconf_mount_clients $CLIENTS $DIR"
        echo "==== $TESTNAME ===== CONNECTION TIME $ELAPSED: FAKE_NUM=$FAKE_NUM CLIENTCOUNT=$CLIENTCOUNT"

        # do_facet mds "lctl set_param mds.${mds_svc}.flush_stale_exports=1"
        delete_fake_exports
    done

    return 0
}
run_test 1b "VBR: connect $CLIENTCOUNT clients with delayed exports"

# Sigh. One more function for mds failover
# fail fn does not do df on all clients
fail_mds () {
    facet_failover mds
    client_df
}

test_1c() {
    zconf_mount_clients $CLIENTS $DIR

    # sanity mds fail (to exclude the recults on fresh formatted fs)
    facet_failover mds

    local current_ts
    local elapsed
    local FAKE_NUM
    local NUM

    for FAKE_NUM in 10 $FAKE_NUM_MAX; do

        NUM=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_exports|wc -l")

        log "===== CREATE FAKE EXPORTS: $FAKE_NUM ( were $NUM )"
        create_fake_exports mds $FAKE_NUM
        NUM=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_exports|wc -l")
        [ $NUM -lt $FAKE_NUM ] && error "fake exports $NUM -ne $FAKE_NUM"
        echo "===== STALE EXPORTS: FAKE_NUM=$FAKE_NUM NUM=$NUM"

        replay_barrier mds
        do_nodes $CLIENTS "createmany -o $DIR/$tfile-\\\$(hostname)" 25
        # XXX For FAILURE_MODE=HARD it is better to exclude
        # shutdown_facet and reboot_facet time 
        fail_mds

        local current_ts=`date +%s`
        local elapsed=`expr $current_ts - $RECOVERY_START_TIME`

        do_nodes $CLIENTS "unlinkmany $DIR/$tfile-\\\$(hostname) 25"
        echo "==== $TESTNAME ===== RECOVERY TIME $elapsed: FAKE_NUM=$FAKE_NUM CLIENTCOUNT=$CLIENTCOUNT"

        # do_facet mds "lctl set_param mds.${mds_svc}.flush_stale_exports=1"
        delete_fake_exports
    done

    return 0
}
run_test 1c "VBR: recovery $CLIENTCOUNT clients with delayed exports"


test_1d() {
    local FAKE_NUM
    local NUM

    for FAKE_NUM in 10 $FAKE_NUM_MAX; do
        zconf_umount_clients $CLIENTS $DIR
        zconf_mount $CLIENT1 $DIR

        NUM=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_exports|wc -l")

        log "===== CREATE FAKE EXPORTS: $FAKE_NUM ( were $NUM )"
        create_fake_exports mds $FAKE_NUM
        NUM=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_exports|wc -l")
        [ $NUM -lt $FAKE_NUM ] && error "fake exports $NUM -lt $FAKE_NUM"
        echo "===== STALE EXPORTS: FAKE_NUM=$FAKE_NUM NUM=$NUM"

        OLD_AGE=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_export_age")
        echo OLD_AGE=$OLD_AGE
        NEW_AGE=10
        do_facet mds "lctl set_param mds.${mds_svc}.stale_export_age=$NEW_AGE"
        sleep $((NEW_AGE + 3))
        EX_NUM=$(do_facet mds "lctl get_param -n mds.${mds_svc}.stale_exports|grep -c EXPIRED")
        [ "$EX_NUM" -eq "$NUM" ] || error "not all exports are expired $EX_NUM != $NUM"

        do_and_time "zconf_mount_clients $CLIENTS $DIR"
        echo "==== $TESTNAME===== CONNECTION TIME $ELAPSED: expired FAKE_NUM=$FAKE_NUM CLIENTCOUNT=$CLIENTCOUNT"

        do_facet mds "lctl set_param mds.${mds_svc}.stale_export_age=$OLD_AGE"
    done

    return 0
}
run_test 1d "VBR: expire exports, connect $CLIENTCOUNT clients"
# VBR scale tests end

equals_msg `basename $0`: test complete, cleaning up
check_and_cleanup_lustre
[ -f "$TESTSUITELOG" ] && cat $TESTSUITELOG || true
