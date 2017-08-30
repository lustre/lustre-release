#!/bin/bash
# vim:shiftwidth=4:softtabstop=4:tabstop=4:

# client failure does not affect other clients

# Start load on clients (each client works on it's own directory).
# At defined (5-10 minutes) interval fail one random client and then fail mds.
# Reintegrate failed client after recovery completed,
# application errors are allowed for that client but not on other clients.
# 10 minute intervals and verify that no application errors occur.

# Test runs one of CLIENT_LOAD progs on remote clients.
set -e

ONLY=${ONLY:-"$*"}

# bug number for skipped test:
ALWAYS_EXCEPT="$RECOVERY_RANDOM_SCALE_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

remote_mds_nodsh && skip_env "remote MDS with nodsh" && exit 0
remote_ost_nodsh && skip_env "remote OST with nodsh" && exit 0

[ -z "$CLIENTS" -o $CLIENTCOUNT -lt 3 ] &&
    skip_env "need three or more clients" && exit 0

if [ -z "$SHARED_DIRECTORY" ] || ! check_shared_dir $SHARED_DIRECTORY; then
    skip_env "SHARED_DIRECTORY should be specified with a shared directory \
which is accessable on all of the nodes"
    exit 0
fi

[[ $FAILURE_MODE = SOFT ]] && \
    log "WARNING: $0 is not functional with FAILURE_MODE = SOFT, bz22797"

# Application failures are allowed for the failed client
# but not for other clients.
ERRORS_OK="yes"

if [ "$SLOW" = "no" ]; then
    DURATION=${DURATION:-$((60 * 30))}
else
    DURATION=${DURATION:-$((60 * 60 * 24))}
fi
SERVER_FAILOVER_PERIOD=${SERVER_FAILOVER_PERIOD:-$((60 * 10))} # 10 minutes

MINSLEEP=${MINSLEEP:-120}
REQFAIL_PERCENT=${REQFAIL_PERCENT:-3}    # bug17839 comment 62
# round up the result of integer division: C=(A + (B - 1)) / B
REQFAIL=${REQFAIL:-$(((DURATION * REQFAIL_PERCENT + (SERVER_FAILOVER_PERIOD *
	100 - 1 )) / SERVER_FAILOVER_PERIOD / 100))}

END_RUN_FILE=${END_RUN_FILE:-$SHARED_DIRECTORY/end_run_file}
LOAD_PID_FILE=${LOAD_PID_FILE:-$TMP/client-load.pid}
VMSTAT_PID_FILE=${VMSTAT_PID_FILE:-$TMP/vmstat.pid}

numfailovers () {
    local facet
    local var

    for facet in $MDTS ${FAILED_CLIENTS//,/ }; do
        var=${facet}_nums
        val=${!var}
        if [ "$val" ] ; then
            echo "$facet failed over $val times"
        fi
    done
}

summary_and_cleanup () {
    local rc=$?
    trap 0

    # Having not empty END_RUN_FILE means the failed loads only
    if [ -s $END_RUN_FILE ]; then
        print_end_run_file $END_RUN_FILE
        rc=1
    fi

    echo $(date +'%F %H:%M:%S') Terminating clients loads ...
    echo "$0" >> $END_RUN_FILE
    local result=PASS
    [ $rc -eq 0 ] || result=FAIL

    log "Duration:               $DURATION
Server failover period: $SERVER_FAILOVER_PERIOD seconds
Exited after:           $ELAPSED seconds
Number of failovers before exit:
$(numfailovers)
Status: $result: rc=$rc"

    # stop vmstat on OSS nodes
    [ "$VMSTAT" ] && stop_process $(comma_list $(osts_nodes)) $VMSTAT_PID_FILE

    # stop the client loads
    stop_client_loads $NODES_TO_USE $LOAD_PID_FILE

	if [ $rc -ne 0 ]; then
		# we are interested in only on failed clients and servers
		local failedclients=$(cat $END_RUN_FILE | grep -v $0)
		gather_logs $(comma_list $(all_server_nodes) $failedclients)
	fi

    exit $rc
}

################################## Main Flow ###################################
build_test_filter

check_and_setup_lustre
rm -rf $DIR/[Rdfs][0-9]*

MAX_RECOV_TIME=$(max_recovery_time)

# The test node needs to be insulated from a lustre failure as much as possible,
# so not even loading the lustre modules is ideal.
# -- umount lustre
# -- remove hostname from clients list
zconf_umount $HOSTNAME $MOUNT
NODES_TO_USE=${NODES_TO_USE:-$CLIENTS}
NODES_TO_USE=$(exclude_items_from_list $NODES_TO_USE $HOSTNAME)

check_progs_installed $NODES_TO_USE ${CLIENT_LOADS[@]}

MDTS=$(get_facets MDS)

# Fail a random client and then failover a random MDS.
test_fail_client_mds() {
    local fail_client
    local serverfacet
    local client_var
    local var

    trap summary_and_cleanup EXIT INT

    # start vmstat on OSS nodes
    [ "$VMSTAT" ] && start_vmstat $(comma_list $(osts_nodes)) $VMSTAT_PID_FILE

    # start client loads
    rm -f $END_RUN_FILE
    start_client_loads $NODES_TO_USE

    echo client loads pids:
    do_nodesv $NODES_TO_USE "cat $LOAD_PID_FILE" || exit 3

    ELAPSED=0
    local sleep=0
    local reqfail=0
    local it_time_start
    local start_ts=$(date +%s)
    local current_ts=$start_ts

    while [ $ELAPSED -lt $DURATION -a ! -e $END_RUN_FILE ]; do
        # In order to perform the
        # expected number of failovers, we need to account the following:
        # 1) the time that has elapsed during the client load checking
        # 2) time takes for failover
        it_time_start=$(date +%s)

        fail_client=$(get_random_entry $NODES_TO_USE)
        client_var=$(node_var_name $fail_client)_nums

        # store the list of failed clients
        # lists are comma separated
        FAILED_CLIENTS=$(expand_list $FAILED_CLIENTS $fail_client)

        serverfacet=$(get_random_entry $MDTS)
        var=${serverfacet}_nums

        # Check that our client loads are still running. If any have died,
        # that means they have died outside of recovery, which is unacceptable.
        log "==== Checking the clients loads BEFORE failover -- failure NOT OK \
             ELAPSED=$ELAPSED DURATION=$DURATION PERIOD=$SERVER_FAILOVER_PERIOD"
        check_client_loads $NODES_TO_USE || exit 4

        log "FAIL CLIENT $fail_client..."
        shutdown_client $fail_client

        log "Starting failover on $serverfacet"
        facet_failover "$serverfacet" || exit 1

        if ! wait_recovery_complete $serverfacet; then
            echo "$serverfacet recovery is not completed!"
            exit 7
        fi

        boot_node $fail_client
        echo "Reintegrating $fail_client"
        zconf_mount $fail_client $MOUNT || exit $?
        client_up $fail_client || exit $?

        # Increment the number of failovers
        val=$((${!var} + 1))
        eval $var=$val
        val=$((${!client_var} + 1))
        eval $client_var=$val

        # load script on failed clients could create END_RUN_FILE
        # We shuold remove it and ignore the failure if this
        # file contains the failed client only.
        # We can not use ERRORS_OK when start all loads at the start of
        # this script because the application errors allowed for random
        # failed client only, but not for all clients.
        if [ -e $END_RUN_FILE ]; then
            local end_run_node
            read end_run_node < $END_RUN_FILE
            [[ $end_run_node = $fail_client ]] &&
                rm -f $END_RUN_FILE || exit 13
        fi

        restart_client_loads $fail_client $ERRORS_OK || exit $?

        # Check that not failed clients loads are still running.
        # No application failures should occur on clients that were not failed.
        log "==== Checking the clients loads AFTER failed client reintegrated \
-- failure NOT OK"
        if ! ERRORS_OK= check_client_loads \
            $(exclude_items_from_list $NODES_TO_USE $fail_client); then
            log "Client load failed. Exiting..."
            exit 5
        fi

        current_ts=$(date +%s)
        ELAPSED=$((current_ts - start_ts))
        sleep=$((SERVER_FAILOVER_PERIOD - (current_ts - it_time_start)))

        # Keep counting the number of iterations when
        # time spent to failover and two client loads check exceeded
        # the value ( SERVER_FAILOVER_PERIOD - MINSLEEP ).
        if [ $sleep -lt $MINSLEEP ]; then
            reqfail=$((reqfail + 1))
            log "WARNING: failover, client reintegration and \
check_client_loads time exceeded SERVER_FAILOVER_PERIOD - MINSLEEP!
Failed to load the filesystem with I/O for a minimum period of \
$MINSLEEP $reqfail times ( REQFAIL=$REQFAIL ).
This iteration, the load was only applied for sleep=$sleep seconds.
Estimated max recovery time : $MAX_RECOV_TIME
Probably the hardware is taking excessively long time to boot.
Try to increase SERVER_FAILOVER_PERIOD (current is $SERVER_FAILOVER_PERIOD), \
bug 20918"
            [ $reqfail -gt $REQFAIL ] && exit 6
        fi

        log "Number of failovers:
$(numfailovers)                and counting..."

        [ $((ELAPSED + sleep)) -ge $DURATION ] && break

        if [ $sleep -gt 0 ]; then
            echo "sleeping $sleep seconds... "
            sleep $sleep
        fi
    done
    exit 0
}
run_test fail_client_mds "fail client, then failover MDS"

zconf_mount $HOSTNAME $MOUNT || error "mount $MOUNT on $HOSTNAME failed"
client_up || error "start client on $HOSTNAME failed"

complete $SECONDS
check_and_cleanup_lustre
exit_status
