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
init_logging

require_dsh_mds || exit 0

[ -n "$CLIENTS" ] || { skip_env "$0: Need two or more clients" && exit 0; }
[ $CLIENTCOUNT -ge 2 ] || \
    { skip_env "$0: Need two or more remote clients, have $CLIENTCOUNT" && exit 0; }

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
    { skip_env "$0: no version_recovery" && exit 0; }

FAKE_NUM_MAX=${FAKE_NUM_MAX:-1000}
[ "$SLOW" = "no" ] && FAKE_NUM_MAX=100

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
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

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
        local elapsed=$(do_and_time "zconf_mount_clients $CLIENTS $DIR")
        echo "==== $TESTNAME ===== CONNECTION TIME $elapsed: FAKE_NUM=$FAKE_NUM CLIENTCOUNT=$CLIENTCOUNT"

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
    clients_up
}

test_1c() {
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

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
    delayed_recovery_enabled || { skip "No delayed recovery support"; return 0; }

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

        local elapsed=$(do_and_time "zconf_mount_clients $CLIENTS $DIR")
        echo "==== $TESTNAME===== CONNECTION TIME $elapsed: expired FAKE_NUM=$FAKE_NUM CLIENTCOUNT=$CLIENTCOUNT"

        do_facet mds "lctl set_param mds.${mds_svc}.stale_export_age=$OLD_AGE"
    done

    return 0
}
run_test 1d "VBR: expire exports, connect $CLIENTCOUNT clients"
# VBR scale tests end

test_3a() {
    assert_env CLIENTS MDSRATE MPIRUN

    local -a nodes=(${CLIENTS//,/ })

    # INCREMENT is a number of clients
    # a half of clients by default
    increment=${INCREMENT:-$(( CLIENTCOUNT / 2 ))}

    machinefile=${MACHINEFILE:-$TMP/$(basename $0 .sh).machines}
    local LOG=$TMP/${TESTSUITE}_$tfile

    local var=mds_svc
    local procfile="*.${!var}.recovery_status"
    local iters=${ITERS:-3}
    local nfiles=${NFILES:-50000}
    local nthreads=${THREADS_PER_CLIENT:-3}

    local IFree=$(inodes_available)
    [ $IFree -gt $nfiles ] || nfiles=$IFree

    local dir=$DIR/d0.$TESTNAME
    mkdir -p $dir
    chmod 0777 $dir

    local pid
    local list
    local -a res

    local num=$increment

    while [ $num -le $CLIENTCOUNT ]; do
        list=$(comma_list ${nodes[@]:0:$num})

        generate_machine_file $list $machinefile ||
            { error "can not generate machinefile"; exit 1; }

        for i in $(seq $iters); do
            mdsrate_cleanup $num $machinefile $nfiles $dir 'f%%d' --ignore

            COMMAND="${MDSRATE} --create --nfiles $nfiles --dir $dir --filefmt 'f%%d'"
            mpi_run -np $((num * nthreads)) ${MACHINEFILE_OPTION} $machinefile \
                        ${COMMAND} | tee ${LOG} &

            pid=$!
            echo "pid=$pid"

            # 2 threads 100000 creates 117 secs
            sleep 20

            log "$i : Starting failover on mds"
            facet_failover mds
            if ! wait_recovery_complete mds $((TIMEOUT * 10)); then
                echo "mds recovery is not completed!"
                kill -9 $pid
                exit 7
            fi

            duration=$(do_facet mds lctl get_param -n $procfile | grep recovery_duration)

            res=( "${res[@]}" "$num" )
            res=( "${res[@]}" "$duration" )
            echo "RECOVERY TIME: NFILES=$nfiles number of clients: $num  $duration"
            wait $pid

        done
        num=$((num + increment))
    done

    mdsrate_cleanup $num $machinefile $nfiles $dir 'f%%d' --ignore

    i=0
    while [ $i -lt ${#res[@]} ]; do
        echo "RECOVERY TIME: NFILES=$nfiles number of clients: ${res[i]}  ${res[i+1]}"
        i=$((i+2))
    done
}

run_test 3a "recovery time, $CLIENTCOUNT clients"

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
exit_status
